from collections import deque
import os
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
import requests
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="NEXUS Forensic Engine - Phase 2")

origins = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]

prod_origin = os.getenv("FRONTEND_URL")
if prod_origin:
    origins.append(prod_origin)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows requests from any frontend domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

ETHERSCAN_API_KEY = "TVI3TP3ZBXTE641AP7S44FE5966N3J8ID5"
TRON_USDT_CONTRACT = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"

# ---------------------------------------------------------
# 1. KNOWN VASP REGISTRY (Centralized Exchange Hot Wallets)
# ---------------------------------------------------------
KNOWN_VASPS = {
    "0x28c6c06298d514db089934071355e5743bf21d60": {"name": "Binance Hot Wallet 14", "entity": "Binance"},
    "0x21a31ee1afc51d94c2efccaa2092ad1028285549": {"name": "Binance Hot Wallet 8", "entity": "Binance"},
    "0x42981d0bfbaf196529376ee702f2a9eb9092fcb5": {"name": "WazirX Hot Wallet", "entity": "WazirX"},
    "0x70faa28a6b8d6d0ad712415ab1ea49236674a4b5": {"name": "CoinDCX Hot Wallet", "entity": "CoinDCX"},
    "tjmmqjb1dk9ttzbqxzrq2aua94z4gkapfh": {"name": "Binance Tron Hot Wallet", "entity": "Binance"},
}

# ---------------------------------------------------------
# 2. HEURISTIC DUST THRESHOLDS
# ---------------------------------------------------------
DUST_THRESHOLD_WEI = 10**15   # 0.001 ETH
DUST_THRESHOLD_SUN = 10**6    # 1.0 USDT


def fetch_outbound_transactions(wallet_address: str):
    """Fetches outbound transactions across Ethereum (EVM) or Tron networks."""
    outbound = []
    clean_addr = wallet_address.strip().lower()

    # Route A: Ethereum (EVM)
    if clean_addr.startswith("0x"):
        url = (
            f"https://api.etherscan.io/v2/api?chainid=1&module=account&action=txlist"
            f"&address={clean_addr}&startblock=0&endblock=99999999&page=1&offset=25&sort=desc"
            f"&apikey={ETHERSCAN_API_KEY}"
        )
        try:
            res = requests.get(url, timeout=10).json()
            if res.get("status") == "1":
                for tx in res.get("result", []):
                    if tx.get("from", "").lower() == clean_addr and tx.get("to"):
                        val = int(tx.get("value", 0))
                        if val >= DUST_THRESHOLD_WEI:
                            outbound.append({
                                "to": tx.get("to").lower(),
                                "value_raw": str(val),
                                "hash": tx.get("hash"),
                                "timestamp": tx.get("timeStamp"),
                                "asset": "ETH"
                            })
            else:
                logger.warning(f"Etherscan API error for {clean_addr}: {res.get('message', 'Unknown error')}")
        except requests.RequestException as e:
            logger.error(f"Etherscan request failed for {clean_addr}: {e}")
        except (ValueError, KeyError, TypeError) as e:
            logger.error(f"Etherscan response parsing failed for {clean_addr}: {e}")

    # Route B: Tron Network
    elif clean_addr.startswith("t") and len(clean_addr) == 34:
        url = (
            f"https://api.trongrid.io/v1/accounts/{clean_addr}/transactions/trc20"
            f"?only_from=true&limit=25&contract_address={TRON_USDT_CONTRACT}"
        )
        try:
            res = requests.get(url, timeout=10).json()
            if res.get("success"):
                for tx in res.get("data", []):
                    to_addr = tx.get("to")
                    if to_addr:
                        val = int(tx.get("value", 0))
                        if val >= DUST_THRESHOLD_SUN:
                            outbound.append({
                                "to": to_addr.lower(),
                                "value_raw": str(val),
                                "hash": tx.get("transaction_id"),
                                "timestamp": tx.get("block_timestamp"),
                                "asset": "USDT"
                            })
            else:
                logger.warning(f"TronGrid API error for {clean_addr}: {res.get('meta', {}).get('error', 'Unknown error')}")
        except requests.RequestException as e:
            logger.error(f"TronGrid request failed for {clean_addr}: {e}")
        except (ValueError, KeyError, TypeError) as e:
            logger.error(f"TronGrid response parsing failed for {clean_addr}: {e}")
    else:
        logger.warning(f"Unsupported address format: {wallet_address}")

    return outbound


@app.get("/")
def health_check():
    return {"status": "online", "system": "NEXUS Forensics Engine"}


def validate_wallet_address(address: str) -> bool:
    """Validate wallet address format for Ethereum (0x...) or Tron (T...)."""
    clean = address.strip().lower()
    if clean.startswith("0x") and len(clean) == 42:
        return True
    if clean.startswith("t") and len(clean) == 34:
        return True
    return False


@app.get("/api/trace/{wallet_hash}")
def trace_network(
    wallet_hash: str,
    max_hops: int = Query(default=2, ge=1, le=5, description="Maximum BFS hops (1-5)")
):
    """
    Executes a multi-hop Breadth-First Search (BFS) from a suspect wallet.
    Returns Cytoscape-compatible nodes and edges, terminating early upon VASP discovery.
    """
    # Input validation
    if not validate_wallet_address(wallet_hash):
        raise HTTPException(status_code=400, detail="Invalid wallet address format. Must be Ethereum (0x...) or Tron (T...) address.")

    start_wallet = wallet_hash.strip().lower()
    
    queue = deque([(start_wallet, 0)])
    visited = {start_wallet}

    nodes = [{
        "data": {
            "id": start_wallet,
            "label": f"Suspect: {start_wallet[:6]}...{start_wallet[-4:]}",
            "type": "suspect",
            "hop": 0
        }
    }]
    edges = []

    try:
        while queue:
            current_wallet, hop = queue.popleft()

            if hop >= max_hops:
                continue

            outbound_txs = fetch_outbound_transactions(current_wallet)

            for tx in outbound_txs:
                recipient = tx["to"]

                # Record Edge for Graph Visualization
                edges.append({
                    "data": {
                        "id": f"{tx['hash'][:10]}_{current_wallet[:4]}_{recipient[:4]}",
                        "source": current_wallet,
                        "target": recipient,
                        "hash": tx["hash"],
                        "asset": tx["asset"],
                        "hop": hop + 1
                    }
                })

                # Check for VASP Match
                if recipient in KNOWN_VASPS:
                    vasp_info = KNOWN_VASPS[recipient]
                    nodes.append({
                        "data": {
                            "id": recipient,
                            "label": f"{vasp_info['name']} ({vasp_info['entity']})",
                            "type": "vasp",
                            "entity": vasp_info["entity"],
                            "hop": hop + 1
                        }
                    })
                    return {
                        "status": "VASP_IDENTIFIED",
                        "target": start_wallet,
                        "hops_traversed": hop + 1,
                        "terminal_vasp": {
                            "matched_address": recipient,
                            "vasp_name": vasp_info["name"],
                            "entity": vasp_info["entity"],
                            "detected_at_hop": hop + 1,
                            "terminal_tx_hash": tx["hash"]
                        },
                        "graph_data": {"nodes": nodes, "edges": edges}
                    }

                # Enqueue new intermediary wallet for the next hop
                if recipient not in visited:
                    visited.add(recipient)
                    nodes.append({
                        "data": {
                            "id": recipient,
                            "label": f"Mule: {recipient[:6]}...{recipient[-4:]}",
                            "type": "intermediary",
                            "hop": hop + 1
                        }
                    })
                    queue.append((recipient, hop + 1))

        return {
            "status": "TRACE_COMPLETE_NO_VASP",
            "target": start_wallet,
            "hops_traversed": max_hops,
            "terminal_vasp": None,
            "graph_data": {"nodes": nodes, "edges": edges}
        }
    except Exception as e:
        logger.error(f"Trace failed for {start_wallet}: {e}")
        raise HTTPException(status_code=500, detail="Internal server error during trace")