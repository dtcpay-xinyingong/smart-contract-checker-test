"""
Accuracy evaluation script for Smart Contract Checker.
Tests against known addresses and compares with block explorer APIs.

Uses raw HTTP requests (no web3.py dependency required).
"""

import requests

# Known test cases: (address, network, expected_is_contract, description)
KNOWN_TEST_CASES = [
    # EVM Contracts (well-known)
    ("0xdAC17F958D2ee523a2206206994597C13D831ec7", "Ethereum", True, "USDT Contract"),
    ("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", "Ethereum", True, "USDC Contract"),
    ("0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D", "Ethereum", True, "Uniswap V2 Router"),
    ("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", "Ethereum", True, "WETH Contract"),
    ("0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984", "Ethereum", True, "UNI Token"),

    # EVM Wallets (known EOAs - exchange hot wallets)
    ("0x28C6c06298d514Db089934071355E5743bf21d60", "Ethereum", False, "Binance Hot Wallet"),
    ("0x21a31Ee1afC51d94C2eFcCAa2092aD1028285549", "Ethereum", False, "Binance Wallet 2"),

    # Polygon
    ("0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174", "Polygon", True, "USDC on Polygon"),

    # BSC
    ("0x55d398326f99059fF775485246999027B3197955", "BSC", True, "USDT on BSC"),

    # Tron Contracts
    ("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t", "Tron", True, "USDT on Tron"),

    # Tron Wallets
    ("TJYeasypzPLhgBbq2wjGPLKMqWVgBz5Mwt", "Tron", False, "Known Tron Wallet"),

    # Solana Programs
    ("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", "Solana", True, "SPL Token Program"),
    ("11111111111111111111111111111111", "Solana", True, "System Program"),
    ("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL", "Solana", True, "Associated Token Program"),

    # Solana Wallets (known exchange wallets)
    ("5tzFkiKscXHK5ZXCGbXZxdw7gTjjD1mBwuoFbhUvuAi9", "Solana", False, "Binance Hot Wallet"),
]

# RPC endpoints
EVM_NETWORKS = {
    "Ethereum": "https://eth.llamarpc.com",
    "Polygon": "https://polygon-rpc.com",
    "BSC": "https://bsc-dataseed.binance.org",
    "Arbitrum": "https://arb1.arbitrum.io/rpc",
    "Optimism": "https://mainnet.optimism.io",
    "Avalanche": "https://api.avax.network/ext/bc/C/rpc",
    "Base": "https://mainnet.base.org",
}

TRON_API_BASE = "https://api.trongrid.io"

SOLANA_RPC_URL = "https://api.mainnet-beta.solana.com"

# Block explorer APIs
EXPLORER_APIS = {
    "Ethereum": "https://api.etherscan.io/api",
    "Polygon": "https://api.polygonscan.com/api",
    "BSC": "https://api.bscscan.com/api",
}


def check_evm_address(address: str, rpc_url: str) -> dict:
    """Check if an EVM address is a contract using JSON-RPC."""
    try:
        # eth_getCode returns bytecode at address
        response = requests.post(
            rpc_url,
            json={
                "jsonrpc": "2.0",
                "method": "eth_getCode",
                "params": [address, "latest"],
                "id": 1
            },
            timeout=10
        )
        data = response.json()

        if "error" in data:
            return {"error": data["error"].get("message", "RPC error")}

        code = data.get("result", "0x")
        is_contract = code != "0x" and len(code) > 2

        return {"is_contract": is_contract, "code_size": len(code) // 2 - 1 if is_contract else 0}
    except Exception as e:
        return {"error": str(e)}


def check_tron_address(address: str) -> dict:
    """Check if a Tron address is a contract."""
    try:
        response = requests.post(
            f"{TRON_API_BASE}/wallet/getcontract",
            json={"value": address, "visible": True},
            timeout=10
        )
        data = response.json()
        is_contract = "bytecode" in data and len(data.get("bytecode", "")) > 0

        return {"is_contract": is_contract}
    except Exception as e:
        return {"error": str(e)}


def check_solana_address(address: str) -> dict:
    """Check if a Solana address is a program."""
    try:
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
            return {"error": data["error"].get("message", "RPC error")}

        result = data.get("result")
        if not result or not result.get("value"):
            return {"is_contract": False}

        account_info = result["value"]
        owner = account_info.get("owner")
        executable = account_info.get("executable", False)

        # Check if it's a program
        program_loaders = [
            "BPFLoader1111111111111111111111111111111111",
            "BPFLoader2111111111111111111111111111111111",
            "BPFLoaderUpgradeab1e11111111111111111111111",
            "NativeLoader1111111111111111111111111111111",
        ]

        is_program = executable or owner in program_loaders

        return {"is_contract": is_program}
    except Exception as e:
        return {"error": str(e)}


def check_explorer(address: str, network: str) -> dict:
    """Cross-check with block explorer API."""
    if network not in EXPLORER_APIS:
        return {"error": f"No explorer API for {network}"}

    try:
        url = EXPLORER_APIS[network]
        # Use eth_getCode via proxy module
        response = requests.get(
            url,
            params={
                "module": "proxy",
                "action": "eth_getCode",
                "address": address,
                "tag": "latest"
            },
            timeout=10
        )
        data = response.json()
        code = data.get("result", "0x")

        # Handle API errors or deprecation warnings (not valid hex)
        if not code or not code.startswith("0x"):
            return {"error": f"Invalid API response: {code[:50]}..."}

        # Handle various empty code responses
        is_contract = code not in ("0x", "0x0") and len(code) > 4
        return {"is_contract": is_contract}
    except Exception as e:
        return {"error": str(e)}


def run_known_tests() -> list:
    """Run tests against known addresses."""
    results = []

    print("\n" + "="*60)
    print("PART 1: KNOWN ADDRESS TESTS")
    print("="*60 + "\n")

    for address, network, expected, description in KNOWN_TEST_CASES:
        print(f"Testing: {description}")
        print(f"  Address: {address}")
        print(f"  Network: {network}")
        print(f"  Expected: {'Contract' if expected else 'Wallet'}")

        if network == "Tron":
            result = check_tron_address(address)
        elif network == "Solana":
            result = check_solana_address(address)
        else:
            rpc_url = EVM_NETWORKS.get(network)
            if not rpc_url:
                print(f"  Result: SKIP (no RPC for {network})")
                results.append({
                    "address": address,
                    "network": network,
                    "description": description,
                    "status": "skip",
                    "reason": f"No RPC for {network}"
                })
                continue
            result = check_evm_address(address, rpc_url)

        if "error" in result:
            print(f"  Result: ERROR ({result['error']})")
            results.append({
                "address": address,
                "network": network,
                "description": description,
                "expected": expected,
                "status": "error",
                "reason": result["error"]
            })
        else:
            actual = result["is_contract"]
            passed = actual == expected
            status = "PASS" if passed else "FAIL"
            print(f"  Result: {status} (got {'Contract' if actual else 'Wallet'})")
            results.append({
                "address": address,
                "network": network,
                "description": description,
                "expected": expected,
                "actual": actual,
                "status": "pass" if passed else "fail"
            })
        print()

    return results


def run_explorer_comparison() -> list:
    """Compare our results with block explorer APIs."""
    results = []

    print("\n" + "="*60)
    print("PART 2: BLOCK EXPLORER COMPARISON")
    print("="*60 + "\n")

    # Test addresses for comparison
    addresses = [
        ("0xdAC17F958D2ee523a2206206994597C13D831ec7", "Ethereum", "USDT"),
        ("0x28C6c06298d514Db089934071355E5743bf21d60", "Ethereum", "Binance Wallet"),
        ("0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174", "Polygon", "USDC Polygon"),
        ("0x55d398326f99059fF775485246999027B3197955", "BSC", "USDT BSC"),
    ]

    for address, network, description in addresses:
        print(f"Comparing: {description}")
        print(f"  Address: {address}")

        # Our result (via RPC)
        rpc_url = EVM_NETWORKS.get(network)
        our_result = check_evm_address(address, rpc_url)

        # Explorer result
        explorer_result = check_explorer(address, network)

        if "error" in our_result:
            print(f"  Our tool: ERROR ({our_result['error']})")
        else:
            print(f"  Our tool: {'Contract' if our_result['is_contract'] else 'Wallet'}")

        if "error" in explorer_result:
            print(f"  Explorer: ERROR ({explorer_result['error']})")
        else:
            print(f"  Explorer: {'Contract' if explorer_result['is_contract'] else 'Wallet'}")

        # Compare
        if "error" not in our_result and "error" not in explorer_result:
            match = our_result["is_contract"] == explorer_result["is_contract"]
            print(f"  Match: {'YES' if match else 'NO'}")
            results.append({
                "address": address,
                "network": network,
                "description": description,
                "our_result": our_result["is_contract"],
                "explorer_result": explorer_result["is_contract"],
                "match": match
            })
        else:
            results.append({
                "address": address,
                "network": network,
                "description": description,
                "status": "error"
            })
        print()

    return results


def generate_report(known_results: list, explorer_results: list):
    """Generate a summary report."""
    print("\n" + "="*60)
    print("ACCURACY REPORT")
    print("="*60 + "\n")

    # Known tests summary
    passed = sum(1 for r in known_results if r.get("status") == "pass")
    failed = sum(1 for r in known_results if r.get("status") == "fail")
    errors = sum(1 for r in known_results if r.get("status") == "error")
    skipped = sum(1 for r in known_results if r.get("status") == "skip")
    total = len(known_results)

    print("Known Address Tests:")
    print(f"  Passed:  {passed}/{total}")
    print(f"  Failed:  {failed}/{total}")
    print(f"  Errors:  {errors}/{total}")
    print(f"  Skipped: {skipped}/{total}")

    if passed + failed > 0:
        accuracy = (passed / (passed + failed)) * 100
        print(f"  Accuracy: {accuracy:.1f}%")

    # Explorer comparison summary
    matches = sum(1 for r in explorer_results if r.get("match") is True)
    mismatches = sum(1 for r in explorer_results if r.get("match") is False)
    exp_errors = sum(1 for r in explorer_results if r.get("status") == "error")

    print("\nExplorer Comparison:")
    print(f"  Matches:    {matches}/{len(explorer_results)}")
    print(f"  Mismatches: {mismatches}/{len(explorer_results)}")
    print(f"  Errors:     {exp_errors}/{len(explorer_results)}")

    if matches + mismatches > 0:
        agreement = (matches / (matches + mismatches)) * 100
        print(f"  Agreement:  {agreement:.1f}%")

    # Overall verdict
    print("\n" + "-"*60)
    if failed == 0 and mismatches == 0:
        print("VERDICT: Tool is ACCURATE")
    elif failed > 0:
        print(f"VERDICT: {failed} known test(s) FAILED - review needed")
        for r in known_results:
            if r.get("status") == "fail":
                print(f"  - {r['description']}: expected {'Contract' if r['expected'] else 'Wallet'}, got {'Contract' if r['actual'] else 'Wallet'}")
    elif mismatches > 0:
        print(f"VERDICT: {mismatches} explorer comparison(s) MISMATCHED - review needed")
    print("-"*60)


if __name__ == "__main__":
    print("Smart Contract Checker - Accuracy Evaluation")
    print("=" * 60)

    known_results = run_known_tests()
    explorer_results = run_explorer_comparison()
    generate_report(known_results, explorer_results)
