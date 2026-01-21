import streamlit as st
from web3 import Web3
import re
import concurrent.futures

st.set_page_config(page_title="Smart Contract Checker", page_icon="🔍")

st.title("Smart Contract Checker")
st.write("Check if an address is a smart contract or a regular wallet across multiple networks.")

# Supported networks
networks = {
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
    placeholder="0x...",
    help="Enter a valid address (42 characters starting with 0x)"
)

def is_valid_address(address: str) -> bool:
    """Check if the address is a valid EVM address format."""
    if not address:
        return False
    return bool(re.match(r"^0x[a-fA-F0-9]{40}$", address))

def check_single_network(network_name: str, rpc_url: str, address: str) -> dict:
    """Check if an address is a smart contract on a single network."""
    try:
        w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={'timeout': 10}))

        if not w3.is_connected():
            return {"network": network_name, "error": "Connection failed"}

        checksum_address = Web3.to_checksum_address(address)
        code = w3.eth.get_code(checksum_address)
        balance = w3.eth.get_balance(checksum_address)

        return {
            "network": network_name,
            "is_contract": len(code) > 0,
            "code_size": len(code),
            "balance": w3.from_wei(balance, "ether"),
        }
    except Exception as e:
        return {"network": network_name, "error": str(e)}

def check_all_networks(address: str) -> list:
    """Check address across all networks in parallel."""
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(networks)) as executor:
        futures = {
            executor.submit(check_single_network, name, url, address): name
            for name, url in networks.items()
        }
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())
    return sorted(results, key=lambda x: x["network"])

# Check button
if st.button("Check Address", type="primary"):
    if not is_valid_address(address_input):
        st.error("Please enter a valid address (42 characters starting with 0x)")
    else:
        with st.spinner("Checking across all networks..."):
            results = check_all_networks(address_input)

        st.divider()

        # Show checksum address
        st.code(Web3.to_checksum_address(address_input), language=None)

        # Display results in columns
        for result in results:
            if "error" in result:
                st.warning(f"**{result['network']}**: Could not connect")
            else:
                col1, col2, col3 = st.columns([2, 2, 2])
                with col1:
                    st.write(f"**{result['network']}**")
                with col2:
                    if result["is_contract"]:
                        st.write("✅ Smart Contract")
                    else:
                        st.write("👛 Wallet")
                with col3:
                    st.write(f"{result['balance']:.6f}")

st.divider()
st.caption("Checks all EVM-compatible networks simultaneously. A smart contract has bytecode deployed at its address.")
