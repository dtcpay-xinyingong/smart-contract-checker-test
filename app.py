import streamlit as st
from web3 import Web3
import re
import concurrent.futures
import requests
import json
import os
from datetime import datetime

FEEDBACK_FILE = os.path.join(os.path.dirname(__file__), "feedback.json")

def load_feedback() -> list:
    """Load feedback from file."""
    try:
        with open(FEEDBACK_FILE, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []

def save_feedback(entry: dict):
    """Save a feedback entry to file."""
    feedback = load_feedback()
    feedback.append(entry)
    with open(FEEDBACK_FILE, "w") as f:
        json.dump(feedback, f, indent=2)

def track_recent_check(input_value: str, input_type: str, network: str, result: str):
    """Track recent checks in session state (max 5)."""
    if "recent_checks" not in st.session_state:
        st.session_state["recent_checks"] = []

    entry = {
        "input": input_value,
        "type": input_type,
        "network": network,
        "result": result,
        "timestamp": datetime.now().isoformat()
    }

    # Remove duplicate if exists
    st.session_state["recent_checks"] = [
        c for c in st.session_state["recent_checks"] if c["input"] != input_value
    ]

    # Add to front and keep max 5
    st.session_state["recent_checks"].insert(0, entry)
    st.session_state["recent_checks"] = st.session_state["recent_checks"][:5]

# Default configuration (used if config.json is missing)
DEFAULT_CONFIG = {
    "evm_networks": {
        "Ethereum": "https://eth.llamarpc.com",
        "Polygon": "https://polygon-rpc.com",
        "BSC": "https://bsc-dataseed.binance.org",
        "Arbitrum": "https://arb1.arbitrum.io/rpc",
        "Optimism": "https://mainnet.optimism.io",
        "Avalanche": "https://api.avax.network/ext/bc/C/rpc",
        "Base": "https://mainnet.base.org",
    },
    "tron": {
        "api_base_url": "https://api.trongrid.io"
    },
    "solana": {
        "rpc_url": "https://api.mainnet.solana.com"
    },
    "erc4337": {
        "entrypoints": [
            "0x5ff137d4b0fdcd49dca30c7cf57e578a026d2789",
            "0x0000000071727de22e5e9d8baf0edac6f37da032"
        ],
        "handle_ops_selectors": [
            "0x1fad948c",
            "0x765e827f"
        ]
    }
}

def load_config():
    """Load configuration from config.json, falling back to defaults."""
    config_path = os.path.join(os.path.dirname(__file__), "config.json")
    try:
        with open(config_path, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return DEFAULT_CONFIG

# Load configuration
config = load_config()

# EVM networks
evm_networks = config.get("evm_networks", DEFAULT_CONFIG["evm_networks"])

# Tron API base URL
TRON_API_BASE = config.get("tron", {}).get("api_base_url", "https://api.trongrid.io")

# Solana RPC URL
SOLANA_RPC_URL = config.get("solana", {}).get("rpc_url", "https://api.mainnet.solana.com")

# ERC-4337 EntryPoint contracts
ERC4337_ENTRYPOINTS = set(config.get("erc4337", {}).get("entrypoints", DEFAULT_CONFIG["erc4337"]["entrypoints"]))

# handleOps function selectors
HANDLE_OPS_SELECTORS = set(config.get("erc4337", {}).get("handle_ops_selectors", DEFAULT_CONFIG["erc4337"]["handle_ops_selectors"]))

st.set_page_config(page_title="Smart Contract Checker", page_icon="🔍")

# Sidebar FAQ
with st.sidebar:
    st.header("FAQ")

    with st.expander("How does this tool work?"):
        st.markdown("""
        This tool checks if **bytecode exists** at an address - the same method used by Etherscan and block explorers.

        - **Has bytecode** → Smart Contract
        - **No bytecode** → Wallet (EOA)
        """)

    with st.expander("Is it accurate?"):
        st.markdown("""
        **Yes, for most cases:**

        | Scenario | Result |
        |----------|--------|
        | Deployed contract | ✅ Contract |
        | Regular wallet | 💰 Wallet |
        | Self-destructed contract | 💰 Wallet |
        | Proxy contract | ✅ Contract |
        | CREATE2 (not deployed) | 💰 Wallet |
        """)

    with st.expander("What is ERC-4337?"):
        st.markdown("""
        **Account Abstraction** allows smart contracts to act as wallets.

        When you check an ERC-4337 transaction, this tool extracts the **actual sender** (smart wallet) from the bundler transaction.
        """)

    with st.expander("Why does a network fail?"):
        st.markdown("""
        Public RPCs may occasionally timeout or be rate-limited.

        **Solution:** Try again in a few seconds.
        """)

    with st.expander("What do confidence levels mean?"):
        st.markdown("""
        <small>

        Confidence scores indicate how certain we are about the classification:

        **100% Confidence - Definitely a Contract/Program**
        - Bytecode exists on-chain (EVM/Tron) OR account is executable/owned by program loader (Solana)
        - This is definitive proof of a smart contract/program

        **95% Confidence - Very Likely a Wallet**
        - No bytecode/program code found
        - Has balance (tokens/coins)
        - Almost certainly a regular wallet/EOA that has been used

        **75% Confidence - Probably a Wallet**
        - No bytecode/program code found
        - Zero balance (never used)
        - Most likely an unused wallet address

        **Network-Specific Notes:**
        - **EVM Networks** (Ethereum, Polygon, BSC, etc.): A 75% confidence address could theoretically be a CREATE2 pre-computed address waiting for contract deployment, though this is rare.
        - **Solana**: Uses Program Derived Addresses (PDAs), not CREATE2. A 75% confidence result is almost certainly just an unused wallet.
        - **Tron**: Similar to EVM but CREATE2 is less common. 75% confidence is likely an unused wallet.

        </small>
        """, unsafe_allow_html=True)

    st.divider()
    st.caption("Supported: Ethereum, Polygon, BSC, Arbitrum, Optimism, Avalanche, Base, Tron, Solana")
    st.caption("💡 Special thanks to Valencia for contributing this idea")

st.title("Smart Contract Checker")
st.write("Check if an address or transaction sender is a smart contract or a regular wallet.")

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

def is_valid_solana_address(address: str) -> bool:
    """Check if the address is a valid Solana address format."""
    if not address:
        return False
    # Solana addresses are base58-encoded, typically 32-44 characters
    # Valid base58 characters (no 0, O, I, l)
    return bool(re.match(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$", address))

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
            f"{TRON_API_BASE}/wallet/getcontract",
            json={"value": address, "visible": True},
            timeout=10
        )
        contract_data = contract_response.json()

        # If bytecode exists, it's a contract
        is_contract = "bytecode" in contract_data and len(contract_data.get("bytecode", "")) > 0

        # Get balance from account endpoint
        account_response = requests.get(
            f"{TRON_API_BASE}/v1/accounts/{address}",
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

def check_solana_address(address: str) -> dict:
    """Check if a Solana address is a program (smart contract)."""
    try:
        # Use getAccountInfo to check if it's a program
        response = requests.post(
            SOLANA_RPC_URL,
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getAccountInfo",
                "params": [
                    address,
                    {"encoding": "jsonParsed"}
                ]
            },
            timeout=10
        )
        data = response.json()

        if "error" in data:
            return {"network": "Solana", "error": data["error"].get("message", "RPC error")}

        result = data.get("result")
        if not result or not result.get("value"):
            # Account doesn't exist
            return {
                "network": "Solana",
                "is_contract": False,
                "balance": 0.0,
                "confidence": 75,
            }

        account_info = result["value"]
        owner = account_info.get("owner")
        lamports = account_info.get("lamports", 0)
        balance_sol = lamports / 1_000_000_000  # Convert lamports to SOL
        executable = account_info.get("executable", False)

        # Check if it's a program (executable or owned by program loaders)
        program_loaders = [
            "BPFLoader1111111111111111111111111111111111",
            "BPFLoader2111111111111111111111111111111111",
            "BPFLoaderUpgradeab1e11111111111111111111111",
            "NativeLoader1111111111111111111111111111111",
        ]

        is_program = executable or owner in program_loaders

        # Calculate confidence score
        if is_program:
            confidence = 100  # Executable or owned by loader = definitely a program
        elif balance_sol > 0:
            confidence = 95  # Not a program but has balance = very likely a wallet
        else:
            confidence = 75  # No indication of program, no balance = could be unused

        return {
            "network": "Solana",
            "is_contract": is_program,
            "balance": balance_sol,
            "confidence": confidence,
        }
    except Exception as e:
        return {"network": "Solana", "error": str(e)}

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
        bundler_address = None

        # Check if this is an ERC-4337 transaction
        # Convert to_address to string for comparison
        to_address_str = str(to_address).lower() if to_address else ""
        if to_address_str in ERC4337_ENTRYPOINTS:
            input_data = tx.get("input", b"")
            # Convert HexBytes/bytes to hex string if needed
            if hasattr(input_data, 'hex'):
                input_data = "0x" + input_data.hex()
            elif isinstance(input_data, bytes):
                input_data = "0x" + input_data.hex()
            elif isinstance(input_data, str) and not input_data.startswith("0x"):
                input_data = "0x" + input_data
            userop_sender = parse_erc4337_sender(input_data)
            if userop_sender:
                bundler_address = from_address  # Store the bundler before overwriting
                from_address = userop_sender
                is_erc4337 = True

        return {
            "network": network_name,
            "from_address": from_address,
            "to_address": to_address,
            "is_erc4337": is_erc4337,
            "bundler_address": bundler_address,
        }
    except Exception as e:
        return {"network": network_name, "error": str(e)}

def get_tron_tx_sender(tx_hash: str) -> dict:
    """Get the sender address of a Tron transaction."""
    try:
        response = requests.get(
            f"{TRON_API_BASE}/v1/transactions/{tx_hash}",
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
tab1, tab2, tab3, tab4 = st.tabs(["Address Check", "Transaction Check", "Report Discrepancy", "Past Reported Discrepancies"])

with tab1:
    # Address input
    address_input = st.text_input(
        "Enter Address",
        placeholder="0x... (EVM), T... (Tron), or Solana address",
        help="Enter a valid EVM address (0x...), Tron address (T...), or Solana address",
        key="address_input"
    )

    # Auto-scan when valid address is entered
    is_evm = is_valid_evm_address(address_input)
    is_tron = is_valid_tron_address(address_input)
    is_solana = is_valid_solana_address(address_input)

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

        # Table header
        col1, col2, col3, col4 = st.columns([2, 2, 1, 2])
        with col1:
            st.caption("Network")
        with col2:
            st.caption("Type")
        with col3:
            st.caption("Confidence")
        with col4:
            st.caption("Balance")

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

        # Track this check for reporting
        is_contract = any(r.get("is_contract") for r in successful_results)
        track_recent_check(
            Web3.to_checksum_address(address_input),
            "address",
            "EVM (multiple)",
            "Contract" if is_contract else "Wallet"
        )

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

            # Table header
            col1, col2, col3, col4 = st.columns([2, 2, 1, 2])
            with col1:
                st.caption("Network")
            with col2:
                st.caption("Type")
            with col3:
                st.caption("Confidence")
            with col4:
                st.caption("Balance")

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

            # Track this check for reporting
            track_recent_check(
                address_input,
                "address",
                "Tron",
                "Contract" if result["is_contract"] else "Wallet"
            )

    elif is_solana:
        with st.spinner("Checking Solana network..."):
            result = check_solana_address(address_input)

        st.divider()
        st.code(address_input, language=None)

        if "error" in result:
            st.error(f"Error: {result['error']}")
        else:
            # Summary
            if result["is_contract"]:
                st.success(f"**Summary:** This address is a **Program (Smart Contract)**. (Confidence: {result['confidence']}%)")
            else:
                st.info(f"**Summary:** This address is a **Wallet** (not a program). (Confidence: {result['confidence']}%)")

            # Table header
            col1, col2, col3, col4 = st.columns([2, 2, 1, 2])
            with col1:
                st.caption("Network")
            with col2:
                st.caption("Type")
            with col3:
                st.caption("Confidence")
            with col4:
                st.caption("Balance")

            col1, col2, col3, col4 = st.columns([2, 2, 1, 2])
            with col1:
                st.write(f"**{result['network']}**")
            with col2:
                if result["is_contract"]:
                    st.write("✅ Program")
                else:
                    st.write("💰 Wallet")
            with col3:
                st.write(f"{result['confidence']}%")
            with col4:
                st.write(f"{result['balance']:.9f} SOL")

            # Track this check for reporting
            track_recent_check(
                address_input,
                "address",
                "Solana",
                "Contract" if result["is_contract"] else "Wallet"
            )

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
            to_address = tx_info.get("to_address")
            if is_erc4337:
                bundler_address = tx_info.get("bundler_address")
                st.write(f"**From (Smart Wallet):** `{from_address}`")
                if bundler_address:
                    st.write(f"**From (Bundler):** `{bundler_address}`")
                if to_address:
                    st.write(f"**To (EntryPoint):** `{to_address}`")
                st.caption("This is an ERC-4337 Account Abstraction transaction.")
            else:
                st.write(f"**From:** `{from_address}`")
                if to_address:
                    st.write(f"**To:** `{to_address}`")

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
                    st.success(f"**Summary:** The sender (`{from_address}`) is a **Smart Contract**. (Confidence: {address_result['confidence']}%)")
                else:
                    st.info(f"**Summary:** The sender (`{from_address}`) is a **Wallet** (not a smart contract). (Confidence: {address_result['confidence']}%)")

                # Table header
                col1, col2, col3, col4 = st.columns([2, 2, 1, 2])
                with col1:
                    st.caption("Network")
                with col2:
                    st.caption("Type")
                with col3:
                    st.caption("Confidence")
                with col4:
                    st.caption("Balance")

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

                # Track this check for reporting
                track_recent_check(
                    tx_input,
                    "transaction",
                    network,
                    "Contract" if address_result["is_contract"] else "Wallet"
                )

with tab3:
    st.subheader("Report Discrepancy")
    st.write("Help improve accuracy by reporting incorrect results.")

    # Check if we're in confirmation mode
    if "pending_report" in st.session_state:
        report = st.session_state["pending_report"]
        st.warning(f"**Confirm report:** The result for `{report['input']}` is incorrect?")

        col1, col2 = st.columns(2)
        with col1:
            correct_answer = st.radio(
                "What should the correct result be?",
                ["Contract", "Wallet"],
                index=0 if report.get("tool_result") == "Wallet" else 1,
                key="correct_answer"
            )
        with col2:
            st.write("")
            if report.get("tool_result"):
                st.write(f"**Tool said:** {report['tool_result']}")
            st.write(f"**Network:** {report.get('network', 'Unknown')}")
            st.write(f"**Type:** {report.get('type', 'address').title()}")

        col1, col2 = st.columns(2)
        with col1:
            if st.button("Confirm Report", type="primary"):
                entry = {
                    "timestamp": datetime.now().isoformat(),
                    "type": report.get("type", "address"),
                    "input": report["input"],
                    "network": report.get("network", "Unknown"),
                    "tool_result": report.get("tool_result", "Unknown"),
                    "correct_result": correct_answer,
                    "status": "pending"
                }
                save_feedback(entry)
                del st.session_state["pending_report"]
                st.success("Report submitted! Thank you for helping improve accuracy.")
                st.rerun()
        with col2:
            if st.button("Cancel"):
                del st.session_state["pending_report"]
                st.rerun()

    else:
        # Show recent checks with checkboxes
        recent_checks = st.session_state.get("recent_checks", [])

        if recent_checks:
            st.write("**Select from recent checks:**")
            selected_check = None

            for i, check in enumerate(recent_checks):
                label = f"`{check['input'][:30]}{'...' if len(check['input']) > 30 else ''}` - {check['result']} ({check['network']})"
                if st.checkbox(label, key=f"check_{i}"):
                    selected_check = check

            if selected_check:
                if st.button("Report Selected", type="primary"):
                    st.session_state["pending_report"] = {
                        "input": selected_check["input"],
                        "type": selected_check["type"],
                        "network": selected_check["network"],
                        "tool_result": selected_check["result"]
                    }
                    st.rerun()

            st.divider()

        # Manual entry option
        st.write("**Or enter manually:**")
        manual_input = st.text_input(
            "Address or Transaction Hash",
            placeholder="0x... or T...",
            key="manual_report_input"
        )
        manual_type = st.radio(
            "Type",
            ["Address", "Transaction"],
            horizontal=True,
            key="manual_report_type"
        )

        if manual_input:
            if st.button("Report This", type="secondary"):
                st.session_state["pending_report"] = {
                    "input": manual_input,
                    "type": manual_type.lower(),
                    "network": "Unknown",
                    "tool_result": "Unknown"
                }
                st.rerun()

with tab4:
    st.subheader("Past Reported Discrepancies")

    feedback = load_feedback()
    if feedback:
        st.write(f"**{len(feedback)} reported discrepancy(s)**")

        for entry in reversed(feedback):
            with st.expander(f"{entry['input'][:30]}{'...' if len(entry['input']) > 30 else ''} ({entry['timestamp'][:10]})"):
                col1, col2 = st.columns(2)
                with col1:
                    st.write(f"**Type:** {entry['type'].title()}")
                    st.write(f"**Network:** {entry.get('network', 'Unknown')}")
                    st.write(f"**Status:** {entry.get('status', 'pending').title()}")
                with col2:
                    st.write(f"**Tool said:** {entry.get('tool_result', 'Unknown')}")
                    st.write(f"**Correct result:** {entry['correct_result']}")
                st.code(entry['input'], language=None)
    else:
        st.info("No discrepancies reported yet. Check an address or transaction, then report any incorrect results in the 'Report Discrepancy' tab.")

