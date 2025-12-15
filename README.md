# Atlas - EIP-7702 Smart Contract Wallet

> [!NOTE] > **Audited Contract** ✅  
> Atlas has been [audited by Cantina](https://github.com/Byzantine-Finance/batch-call-and-sponsor/blob/main/audits/Atlas%20-%20Cantina%20Audit%20-%20Dec%202025.pdf) and is ready for production use.

**Atlas** is a smart contract wallet designed to be used with [EIP-7702](https://eips.ethereum.org/EIPS/eip-7702) to enable transaction batching and sponsored transactions for Externally Owned Accounts (EOAs).

## 🌐 Deployed Address

Atlas is deployed at the **same address on all EVM chains**:

```
0x3d965CFdDA791589cCAB955498D509f2F7E30b79
```

This deterministic address was achieved using CREATE2. To deploy Atlas on a chain not supported yet, see the[ Atlas V1 Deployment script](https://github.com/Byzantine-Finance/batch-call-and-sponsor/blob/main/script/Deploy_Atlas_v1.s.sol).

## ✨ Key Features

1. **Batch Execution**: Execute multiple calls atomically in a single transaction
2. **Sponsored Transactions**: Allow third parties (sponsors) to pay gas fees on behalf of the EOA
3. **Replay Protection**: Uses nonces to prevent signature replay attacks
4. **EIP-712 Signatures**: Secure and human-readable signature format
5. **ERC-1271 Support**: Can validate signatures for smart contract interactions

## 🔧 How It Works

EIP-7702 allows EOAs to temporarily or persitently set contract code, enabling them to act as smart contract wallets without deploying a separate contract. This provides a seamless way to add advanced features like batch execution and sponsored transactions to existing EOAs.

## 🚀 Quick Start: Delegate to Atlas

You can delegate your EOA to Atlas using `cast send` with the `--auth` flag. This will enable your EOA to use Atlas's functionality untill you revert the delegation (delegate to the contract address(0)).

### Basic Persistent Delegation

_$PRIVATE_KEY is here the private key the EOA that wants to have code_

```bash
cast send [YOUR_EOA_ADDRESS] \
  --auth 0x3d965CFdDA791589cCAB955498D509f2F7E30b79 \
  --rpc-url $RPC_URL \
  --private-key $PRIVATE_KEY \
  -vvvv
```

## Usage Patterns

#### Pattern 1: Direct Execution (EOA pays gas)

The EOA directly calls Atlas functions after delegating to it:

```solidity
// 1. EOA signs EIP-7702 authorization to delegate to Atlas
// 2. EOA calls directly
Atlas(eoaAddress).executeCall(Call({
    to: target,
    value: 0,
    data: calldata
}));
```

#### Pattern 2: Sponsored Execution (Sponsor pays gas)

A third party (sponsor) pays the gas fees on behalf of the EOA:

```solidity
// 1. EOA signs EIP-7702 authorization to delegate to Atlas
// 2. EOA signs the call off-chain using EIP-712
// 3. Sponsor submits the signature on-chain and pays gas
Atlas(eoaAddress).executeCall(call, deadline, nonce, v, r, s);
```

## 🛡️ Security Considerations

- **Nonce Management**: Each nonce can only be used once to prevent replay attacks
- **Deadline**: Signatures expire after the deadline timestamp
- **Signer Verification**: Only signatures from the EOA itself are valid
- **Authorization**: Direct calls (without signature) can only be made by the EOA itself
- **ERC-7201 Storage**: Uses namespaced storage pattern to avoid storage collisions in case the EOA decides to delegate to another contract.

## 📝 EIP-712 Domain

- **Name**: "Byzantine"
- **Version**: "1"
- **ChainId**: Current chain ID
- **VerifyingContract**: Address of the EOA delegating to Atlas

## 🔗 Related EIPs

- [EIP-7702](https://eips.ethereum.org/EIPS/eip-7702): Set EOA account code for one transaction
- [EIP-712](https://eips.ethereum.org/EIPS/eip-712): Typed structured data hashing and signing
- [EIP-1271](https://eips.ethereum.org/EIPS/eip-1271): Standard Signature Validation Method for Contracts
- [EIP-7201](https://eips.ethereum.org/EIPS/eip-7201): Namespaced storage pattern to avoid storage collisions in case of multiple delegations.

## 🧪 Run Tests

```bash
forge test -vvv
```

The test suite includes:

- Single and batch call execution
- Sponsored transaction flows
- Replay attack prevention
- Signature validation (ERC-1271)
- ERC20, ERC721, and ERC1155 token reception

## 📄 License

MIT

---

Built with ❤️ by [Byzantine](https://github.com/Byzantine-Finance)
