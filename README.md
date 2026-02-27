# Smart Contract Checker

A multi-chain blockchain tool to instantly check if an address or transaction sender is a smart contract or a regular wallet.

## Live Demo

**🚀 Deployed App**: https://smart-contract-checker-test-5kq4akwmi4z8beuumum9xk.streamlit.app/

## Features

- **Multi-Chain Support**: Check addresses across 10+ blockchain networks
  - EVM Networks: Ethereum, Polygon, BSC, Arbitrum, Optimism, Avalanche, Base
  - Tron Network
  - Solana Network

- **Address Verification**: Instantly determine if an address is a smart contract or wallet by checking on-chain bytecode

- **Transaction Analysis**: Extract and verify the sender from any transaction hash

- **ERC-4337 Support**: Special handling for Account Abstraction transactions
  - Automatically extracts the actual smart wallet sender from bundler transactions
  - Identifies EntryPoint contracts

- **Confidence Scoring**:
  - 100% - Bytecode exists (definitely a contract)
  - 95% - No bytecode but has balance (very likely a wallet)
  - 75% - No bytecode, no balance (probably unused wallet)

- **Parallel Network Checking**: Fast concurrent checks across multiple networks

- **Feedback System**: Report discrepancies to improve accuracy

## How It Works

This tool uses the same method as Etherscan and other block explorers:
- **Has bytecode** → Smart Contract
- **No bytecode** → Wallet (EOA)

For Solana, it checks if the account is executable or owned by a program loader.

## Supported Networks

### EVM Networks
- Ethereum
- Polygon
- Binance Smart Chain (BSC)
- Arbitrum
- Optimism
- Avalanche C-Chain
- Base

### Non-EVM Networks
- Tron
- Solana

## Usage

### Address Check
1. Enter any blockchain address (0x... for EVM, T... for Tron, or base58 for Solana)
2. Results appear automatically showing:
   - Contract or Wallet status
   - Confidence level
   - Account balance
   - Network-specific details

### Transaction Check
1. Enter a transaction hash
2. Tool automatically detects which network it belongs to
3. Extracts the sender address
4. Checks if sender is a contract or wallet
5. Special handling for ERC-4337 Account Abstraction transactions

## Local Installation

### Prerequisites
- Python 3.8+
- pip

### Setup

1. Clone the repository:
```bash
git clone https://github.com/dtcpay-xinyingong/smart-contract-checker-test.git
cd smart-contract-checker-test
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Run the app:
```bash
streamlit run app.py
```

4. Open your browser to `http://localhost:8501`

## Configuration

The tool uses `config.json` to configure RPC endpoints and settings. You can customize:

- **EVM Network RPCs**: Add or modify RPC URLs for different networks
- **Tron API**: Change the Tron API base URL
- **Solana RPC**: Configure Solana RPC endpoint
- **ERC-4337 Settings**: Update EntryPoint contracts and function selectors

Example `config.json`:
```json
{
  "evm_networks": {
    "Ethereum": "https://eth.llamarpc.com",
    "Polygon": "https://polygon-rpc.com"
  },
  "tron": {
    "api_base_url": "https://api.trongrid.io"
  },
  "solana": {
    "rpc_url": "https://api.mainnet.solana.com"
  }
}
```

## Tech Stack

- **Frontend**: Streamlit
- **Blockchain Libraries**:
  - Web3.py (EVM networks)
  - Requests (Tron & Solana REST APIs)
- **Concurrency**: ThreadPoolExecutor for parallel network checks

## Accuracy

The tool is highly accurate for most cases:

| Scenario | Result |
|----------|--------|
| Deployed contract | ✅ Contract (100%) |
| Regular wallet | 💰 Wallet (95%+) |
| Self-destructed contract | 💰 Wallet |
| Proxy contract | ✅ Contract (100%) |
| CREATE2 (not deployed) | 💰 Wallet (75%) |

## Known Limitations

- Public RPC endpoints may occasionally timeout or be rate-limited
- CREATE2 addresses show as wallets until contract is deployed
- Requires active internet connection
- Result accuracy depends on RPC endpoint reliability

## FAQ

**Why does a network fail?**
Public RPCs may occasionally timeout or be rate-limited. Try again in a few seconds.

**What is ERC-4337?**
Account Abstraction allows smart contracts to act as wallets. This tool extracts the actual sender (smart wallet) from bundler transactions.

**How confident are the results?**
100% confidence means bytecode was detected. Lower confidence (75-95%) indicates a wallet, with the difference based on whether the address has been used.

## Contributing

Found an incorrect result? Use the "Report Discrepancy" tab in the app to help improve accuracy.

## Acknowledgments

💡 Special thanks to Valencia for contributing the original idea for this tool.

## License

MIT License - feel free to use and modify as needed.

## Contact

For issues or questions, please open an issue on GitHub.
