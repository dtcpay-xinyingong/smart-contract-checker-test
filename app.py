import streamlit as st
from web3 import Web3
import re

st.set_page_config(page_title="Smart Contract Checker", page_icon="🔍")

st.title("Smart Contract Checker")
st.write("Check if an Ethereum address is a smart contract or an externally owned account (EOA).")

# RPC endpoint input - allows any network
rpc_url = st.text_input(
    "RPC URL",
    value="https://eth.llamarpc.com",
    help="Enter the RPC URL for any EVM-compatible network"
)

# Common networks for quick reference
with st.expander("Common RPC URLs"):
    st.markdown("""
    - **Ethereum Mainnet:** `https://eth.llamarpc.com`
    - **Sepolia Testnet:** `https://rpc.sepolia.org`
    - **Polygon Mainnet:** `https://polygon-rpc.com`
    - **BSC Mainnet:** `https://bsc-dataseed.binance.org`
    - **Arbitrum One:** `https://arb1.arbitrum.io/rpc`
    - **Optimism:** `https://mainnet.optimism.io`
    - **Avalanche C-Chain:** `https://api.avax.network/ext/bc/C/rpc`
    - **Base:** `https://mainnet.base.org`
    """)

# Address input
address_input = st.text_input(
    "Enter Ethereum Address",
    placeholder="0x...",
    help="Enter a valid Ethereum address (42 characters starting with 0x)"
)

def is_valid_address(address: str) -> bool:
    """Check if the address is a valid Ethereum address format."""
    if not address:
        return False
    return bool(re.match(r"^0x[a-fA-F0-9]{40}$", address))

def check_smart_contract(rpc_url: str, address: str) -> dict:
    """Check if an address is a smart contract."""
    try:
        w3 = Web3(Web3.HTTPProvider(rpc_url))

        if not w3.is_connected():
            return {"error": "Failed to connect to the network"}

        checksum_address = Web3.to_checksum_address(address)
        code = w3.eth.get_code(checksum_address)
        balance = w3.eth.get_balance(checksum_address)

        is_contract = len(code) > 0

        return {
            "is_contract": is_contract,
            "code_size": len(code),
            "balance": w3.from_wei(balance, "ether"),
            "address": checksum_address
        }
    except Exception as e:
        return {"error": str(e)}

# Check button
if st.button("Check Address", type="primary"):
    if not rpc_url:
        st.error("Please enter a valid RPC URL")
    elif not is_valid_address(address_input):
        st.error("Please enter a valid Ethereum address (42 characters starting with 0x)")
    else:
        with st.spinner("Checking address..."):
            result = check_smart_contract(rpc_url, address_input)

        if "error" in result:
            st.error(f"Error: {result['error']}")
        else:
            st.divider()

            if result["is_contract"]:
                st.success("This address IS a Smart Contract")
                col1, col2 = st.columns(2)
                with col1:
                    st.metric("Contract Code Size", f"{result['code_size']} bytes")
                with col2:
                    st.metric("Balance", f"{result['balance']:.6f} ETH")
            else:
                st.info("This address is NOT a Smart Contract (EOA)")
                st.metric("Balance", f"{result['balance']:.6f} ETH")

            st.code(result["address"], language=None)

st.divider()
st.caption("A smart contract has bytecode deployed at its address, while an EOA (Externally Owned Account) does not.")
