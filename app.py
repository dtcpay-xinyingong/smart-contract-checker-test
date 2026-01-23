import streamlit as st
from web3 import Web3
import re
import concurrent.futures
import requests

st.set_page_config(page_title="Smart Contract Checker", page_icon="🔍")

st.title("Smart Contract Checker")
st.write("Check if an address or transaction sender is a smart contract or a regular wallet.")

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

# ERC-4337 EntryPoint contracts
ERC4337_ENTRYPOINTS = {
    "0x5ff137d4b0fdcd49dca30c7cf57e578a026d2789",  # v0.6
    "0x0000000071727de22e5e9d8baf0edac6f37da032",  # v0.7
}

# handleOps function selectors
HANDLE_OPS_SELECTORS = {
    "0x1fad948c",  # v0.6 handleOps
    "0x765e827f",  # v0.7 handleOps
}

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

def is_valid_evm_tx_hash(tx_hash: str) -> bool:
    """Check if the string is a valid EVM transaction hash format."""
    if not tx_hash:
        return False
    return bool(re.match(r"^0x[a-fA-F0-9]{64}$", tx_hash))

def is_valid_tron_tx_hash(tx_hash: str) -> bool:
    """Check if the string is a valid Tron transaction hash format."""
    if not tx_hash:
        return False
    return bool(re.match(r"^[a-fA-F0-9]{64}$", tx_hash))

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

def parse_erc4337_sender(input_data: str) -> str | None:
    """Extract the UserOp sender from ERC-4337 handleOps calldata."""
    try:
        # Check if this is a handleOps call
        if len(input_data) < 10:
            return None

        selector = input_data[:10].lower()
        if selector not in HANDLE_OPS_SELECTORS:
            return None

        # handleOps(UserOperation[] ops, address beneficiary)
        # After selector (4 bytes), we have:
        # - offset to ops array (32 bytes)
        # - beneficiary address (32 bytes)
        # At ops array offset:
        # - array length (32 bytes)
        # - offset to first UserOp (32 bytes)
        # At first UserOp:
        # - sender address (first 32 bytes, address is in last 20 bytes)

        data = input_data[10:]  # Remove selector

        # Get offset to ops array (first 32 bytes = 64 hex chars)
        ops_offset = int(data[:64], 16) * 2  # Convert to hex char offset

        # At ops array: first 32 bytes is array length
        ops_data = data[ops_offset:]

        # Next 32 bytes is offset to first UserOp
        first_op_offset = int(ops_data[64:128], 16) * 2

        # Get first UserOp data
        first_op_data = ops_data[64 + first_op_offset:]

        # First field of UserOp is sender (address in last 20 bytes of 32-byte word)
        sender_word = first_op_data[:64]
        sender = "0x" + sender_word[-40:]

        return Web3.to_checksum_address(sender)
    except Exception:
        return None

def get_evm_tx_sender(network_name: str, rpc_url: str, tx_hash: str) -> dict:
    """Get the sender address of an EVM transaction."""
    try:
        w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={'timeout': 10}))

        if not w3.is_connected():
            return {"network": network_name, "error": "Connection failed"}

        tx = w3.eth.get_transaction(tx_hash)

        from_address = Web3.to_checksum_address(tx["from"])
        to_address = tx.get("to")
        is_erc4337 = False

        # Check if this is an ERC-4337 transaction
        if to_address and to_address.lower() in ERC4337_ENTRYPOINTS:
            input_data = tx.get("input", b"")
            # Convert HexBytes to hex string if needed
            if hasattr(input_data, 'hex'):
                input_data = "0x" + input_data.hex()
            elif isinstance(input_data, bytes):
                input_data = "0x" + input_data.hex()
            userop_sender = parse_erc4337_sender(input_data)
            if userop_sender:
                from_address = userop_sender
                is_erc4337 = True

        return {
            "network": network_name,
            "from_address": from_address,
            "to_address": to_address,
            "is_erc4337": is_erc4337,
        }
    except Exception as e:
        return {"network": network_name, "error": str(e)}

def get_tron_tx_sender(tx_hash: str) -> dict:
    """Get the sender address of a Tron transaction."""
    try:
        response = requests.get(
            f"https://api.trongrid.io/v1/transactions/{tx_hash}",
            timeout=10
        )
        data = response.json()

        if not data.get("data") or len(data["data"]) == 0:
            return {"network": "Tron", "error": "Transaction not found"}

        tx = data["data"][0]
        # Extract owner_address from raw_data
        raw_data = tx.get("raw_data", {})
        contracts = raw_data.get("contract", [])
        if contracts:
            param_value = contracts[0].get("parameter", {}).get("value", {})
            owner_address = param_value.get("owner_address")
            to_address = param_value.get("to_address") or param_value.get("contract_address")
            return {
                "network": "Tron",
                "from_address": owner_address,
                "to_address": to_address,
            }
        return {"network": "Tron", "error": "Could not parse transaction"}
    except Exception as e:
        return {"network": "Tron", "error": str(e)}

def find_tx_on_all_networks(tx_hash: str) -> dict:
    """Find which network a transaction belongs to by checking all networks."""
    results = []

    # Check if it could be a Tron tx (no 0x prefix)
    is_potential_tron = is_valid_tron_tx_hash(tx_hash)
    is_potential_evm = is_valid_evm_tx_hash(tx_hash)

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(evm_networks) + 1) as executor:
        futures = {}

        # Submit EVM network checks
        if is_potential_evm:
            for name, url in evm_networks.items():
                futures[executor.submit(get_evm_tx_sender, name, url, tx_hash)] = name

        # Submit Tron check
        if is_potential_tron:
            futures[executor.submit(get_tron_tx_sender, tx_hash)] = "Tron"

        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if "error" not in result:
                results.append(result)

    return results

# Create tabs
tab1, tab2 = st.tabs(["Address Check", "Transaction Check"])

with tab1:
    # Address input
    address_input = st.text_input(
        "Enter Address",
        placeholder="0x... (EVM) or T... (Tron)",
        help="Enter a valid EVM address (0x...) or Tron address (T...)",
        key="address_input"
    )

    # Auto-scan when valid address is entered
    is_evm = is_valid_evm_address(address_input)
    is_tron = is_valid_tron_address(address_input)

    if is_evm:
        with st.spinner("Checking across all EVM networks..."):
            results = check_all_evm_networks(address_input)

        st.divider()
        st.code(Web3.to_checksum_address(address_input), language=None)

        # Summary
        successful_results = [r for r in results if "error" not in r]
        if successful_results:
            is_any_contract = any(r["is_contract"] for r in successful_results)
            avg_confidence = sum(r["confidence"] for r in successful_results) / len(successful_results)
            if is_any_contract:
                st.success(f"**Summary:** This address is a **Smart Contract** on at least one network. (Confidence: {avg_confidence:.0f}%)")
            else:
                st.info(f"**Summary:** This address is a **Wallet** (not a smart contract on any checked network). (Confidence: {avg_confidence:.0f}%)")

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

    elif is_tron:
        with st.spinner("Checking Tron network..."):
            result = check_tron_address(address_input)

        st.divider()
        st.code(address_input, language=None)

        if "error" in result:
            st.error(f"Error: {result['error']}")
        else:
            # Summary
            if result["is_contract"]:
                st.success(f"**Summary:** This address is a **Smart Contract**. (Confidence: {result['confidence']}%)")
            else:
                st.info(f"**Summary:** This address is a **Wallet** (not a smart contract). (Confidence: {result['confidence']}%)")

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

with tab2:
    # Transaction hash input
    tx_input = st.text_input(
        "Enter Transaction Hash",
        placeholder="0x... (EVM) or 64-char hex (Tron)",
        help="Enter a valid transaction hash to check if the sender is a smart contract",
        key="tx_input"
    )

    is_potential_evm_tx = is_valid_evm_tx_hash(tx_input)
    is_potential_tron_tx = is_valid_tron_tx_hash(tx_input)

    if is_potential_evm_tx or is_potential_tron_tx:
        with st.spinner("Searching for transaction across all networks..."):
            tx_results = find_tx_on_all_networks(tx_input)

        st.divider()

        if not tx_results:
            st.error("Transaction not found on any network.")
        else:
            # Found the transaction
            tx_info = tx_results[0]  # Use first found result
            network = tx_info["network"]
            from_address = tx_info["from_address"]

            st.code(tx_input, language=None)
            st.write(f"**Found on:** {network}")

            # Check if it's an ERC-4337 transaction
            is_erc4337 = tx_info.get("is_erc4337", False)
            if is_erc4337:
                st.write(f"**From (Smart Wallet):** `{from_address}`")
                st.caption("This is an ERC-4337 Account Abstraction transaction. Showing the smart wallet sender, not the bundler.")
            else:
                st.write(f"**From:** `{from_address}`")

            # Now check if the from address is a contract
            with st.spinner(f"Checking if sender is a smart contract on {network}..."):
                if network == "Tron":
                    address_result = check_tron_address(from_address)
                else:
                    rpc_url = evm_networks.get(network)
                    address_result = check_evm_network(network, rpc_url, from_address)

            if "error" in address_result:
                st.error(f"Error checking address: {address_result['error']}")
            else:
                # Summary
                if address_result["is_contract"]:
                    st.success(f"**Summary:** The sender is a **Smart Contract**. (Confidence: {address_result['confidence']}%)")
                else:
                    st.info(f"**Summary:** The sender is a **Wallet** (not a smart contract). (Confidence: {address_result['confidence']}%)")

                col1, col2, col3, col4 = st.columns([2, 2, 1, 2])
                with col1:
                    st.write(f"**{address_result['network']}**")
                with col2:
                    if address_result["is_contract"]:
                        st.write("✅ Smart Contract")
                    else:
                        st.write("💰 Wallet")
                with col3:
                    st.write(f"{address_result['confidence']}%")
                with col4:
                    balance = address_result['balance']
                    unit = "TRX" if network == "Tron" else ""
                    st.write(f"{balance:.6f} {unit}".strip())

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
