import streamlit as st
from web3 import Web3
import re
import concurrent.futures
import requests

st.set_page_config(page_title="Smart Contract Checker", page_icon="🔍")

st.title("Smart Contract Checker")
st.write("Check if an address is a smart contract or a regular wallet across multiple networks.")

# EVM networks
evm_networks = {
    "Ethereum": "https://eth.llamarpc.com",
    "Polygon": "https://polygon-rpc.com",
    "BSC": "https://bsc-dataseed.binance.org",
    "Arbitrum": "https://arb1.arbitrum.io/rpc",
    "Optimism": "https://mainnet.optimism.io",
    "Avalanche": "https://api.avax.network/ext/bc/C/rpc",
    "Base": "https://mainnet.base.org",
}

# Address input
address_input = st.text_input(
    "Enter Address",
    placeholder="0x... (EVM) or T... (Tron)",
    help="Enter a valid EVM address (0x...) or Tron address (T...)"
)

def is_valid_evm_address(address: str) -> bool:
    """Check if the address is a valid EVM address format."""
    if not address:
        return False
    return bool(re.match(r"^0x[a-fA-F0-9]{40}$", address))

def is_valid_tron_address(address: str) -> bool:
    """Check if the address is a valid Tron address format."""
    if not address:
        return False
    return bool(re.match(r"^T[a-zA-Z0-9]{33}$", address))

def check_evm_network(network_name: str, rpc_url: str, address: str) -> dict:
    """Check if an address is a smart contract on an EVM network."""
    try:
        w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={'timeout': 10}))

        if not w3.is_connected():
            return {"network": network_name, "error": "Connection failed"}

        checksum_address = Web3.to_checksum_address(address)
        code = w3.eth.get_code(checksum_address)
        balance = w3.eth.get_balance(checksum_address)

        is_contract = len(code) > 0
        code_size = len(code)
        bal = float(w3.from_wei(balance, "ether"))

        # Calculate confidence score
        if is_contract:
            confidence = 100  # Bytecode exists = definitely a contract
        elif bal > 0:
            confidence = 95  # No code but has balance = very likely a wallet
        else:
            confidence = 75  # No code, no balance = could be unused or CREATE2 pending

        return {
            "network": network_name,
            "is_contract": is_contract,
            "code_size": code_size,
            "balance": bal,
            "confidence": confidence,
        }
    except Exception as e:
        return {"network": network_name, "error": str(e)}

def check_tron_address(address: str) -> dict:
    """Check if a Tron address is a smart contract."""
    try:
        # Check if it's a contract using the contract endpoint
        contract_response = requests.post(
            "https://api.trongrid.io/wallet/getcontract",
            json={"value": address, "visible": True},
            timeout=10
        )
        contract_data = contract_response.json()

        # If bytecode exists, it's a contract
        is_contract = "bytecode" in contract_data and len(contract_data.get("bytecode", "")) > 0

        # Get balance from account endpoint
        account_response = requests.get(
            f"https://api.trongrid.io/v1/accounts/{address}",
            timeout=10
        )
        account_data = account_response.json()

        balance_trx = 0.0
        if account_data.get("data") and len(account_data["data"]) > 0:
            balance_sun = account_data["data"][0].get("balance", 0)
            balance_trx = balance_sun / 1_000_000

        # Calculate confidence score
        if is_contract:
            confidence = 100  # Bytecode exists = definitely a contract
        elif balance_trx > 0:
            confidence = 95  # No code but has balance = very likely a wallet
        else:
            confidence = 75  # No code, no balance = could be unused address

        return {
            "network": "Tron",
            "is_contract": is_contract,
            "balance": balance_trx,
            "confidence": confidence,
        }
    except Exception as e:
        return {"network": "Tron", "error": str(e)}

def check_all_evm_networks(address: str) -> list:
    """Check address across all EVM networks in parallel."""
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(evm_networks)) as executor:
        futures = {
            executor.submit(check_evm_network, name, url, address): name
            for name, url in evm_networks.items()
        }
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())
    return sorted(results, key=lambda x: x["network"])

# Auto-scan when valid address is entered
is_evm = is_valid_evm_address(address_input)
is_tron = is_valid_tron_address(address_input)

if is_evm:
    with st.spinner("Checking across all EVM networks..."):
        results = check_all_evm_networks(address_input)

    st.divider()
    st.code(Web3.to_checksum_address(address_input), language=None)

    for result in results:
        if "error" in result:
            st.warning(f"**{result['network']}**: Could not connect")
        else:
            col1, col2, col3, col4 = st.columns([2, 2, 1, 2])
            with col1:
                st.write(f"**{result['network']}**")
            with col2:
                if result["is_contract"]:
                    st.write("✅ Smart Contract")
                else:
                    st.write("💰 Wallet")
            with col3:
                st.write(f"{result['confidence']}%")
            with col4:
                st.write(f"{result['balance']:.6f}")

    # Summary
    successful_results = [r for r in results if "error" not in r]
    if successful_results:
        is_any_contract = any(r["is_contract"] for r in successful_results)
        avg_confidence = sum(r["confidence"] for r in successful_results) / len(successful_results)
        st.divider()
        if is_any_contract:
            st.success(f"**Summary:** This address is a **Smart Contract** on at least one network. (Confidence: {avg_confidence:.0f}%)")
        else:
            st.info(f"**Summary:** This address is a **Wallet** (not a smart contract on any checked network). (Confidence: {avg_confidence:.0f}%)")

elif is_tron:
    with st.spinner("Checking Tron network..."):
        result = check_tron_address(address_input)

    st.divider()
    st.code(address_input, language=None)

    if "error" in result:
        st.error(f"Error: {result['error']}")
    else:
        col1, col2, col3, col4 = st.columns([2, 2, 1, 2])
        with col1:
            st.write(f"**{result['network']}**")
        with col2:
            if result["is_contract"]:
                st.write("✅ Smart Contract")
            else:
                st.write("💰 Wallet")
        with col3:
            st.write(f"{result['confidence']}%")
        with col4:
            st.write(f"{result['balance']:.6f} TRX")

        if result.get("note"):
            st.caption(result["note"])

        # Summary
        st.divider()
        if result["is_contract"]:
            st.success(f"**Summary:** This address is a **Smart Contract**. (Confidence: {result['confidence']}%)")
        else:
            st.info(f"**Summary:** This address is a **Wallet** (not a smart contract). (Confidence: {result['confidence']}%)")

st.divider()

with st.expander("How accurate is this tool?"):
    st.markdown("""
    This tool checks if bytecode exists at an address - the same method used by Etherscan and Tronscan.

    **EVM Networks (Ethereum, Polygon, BSC, etc.)**
    | Scenario | Result | Accurate? |
    |----------|--------|-----------|
    | Deployed contract | ✅ Smart Contract | Yes |
    | Regular wallet | 💰 Wallet | Yes |
    | Self-destructed contract | 💰 Wallet | Yes (bytecode was deleted) |
    | CREATE2 pre-computed address | 💰 Wallet | Yes (not yet deployed) |
    | Proxy contract | ✅ Smart Contract | Yes (but logic lives elsewhere) |

    **Tron**
    | Scenario | Result | Accurate? |
    |----------|--------|-----------|
    | TRC-20/TRC-721 contract | ✅ Smart Contract | Yes |
    | Regular wallet | 💰 Wallet | Yes |
    | Never-used address | 💰 Wallet | Yes |

    **Note:** Public RPCs may occasionally timeout or fail. If a network shows "Could not connect", try again.
    """)
