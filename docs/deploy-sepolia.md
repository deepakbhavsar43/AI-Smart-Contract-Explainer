# Deploy the sample contracts to Sepolia (for the address-lookup demo)

Uses Remix in the browser. You only need MetaMask with a little Sepolia ETH from a faucet.

1. Open https://remix.ethereum.org and create files from `samples/VulnerableBank.sol`, `samples/UnprotectedVault.sol`, `samples/CentralizedToken.sol` and `samples/SafeBank.sol`. `SafeBank` imports OpenZeppelin; Remix resolves `@openzeppelin/...` imports automatically.
2. **Solidity compiler** tab: pick 0.8.20 or newer and compile each file.
3. **Deploy & run** tab: set *Environment* to *Injected Provider - MetaMask* and make sure MetaMask is on Sepolia.
4. Deploy each contract. `CentralizedToken` needs a constructor argument, e.g. `1000000000000000000000000` (1M tokens with 18 decimals).
5. Verify the source so the app can fetch it:
   - In Remix, enable the **Contract Verification** plugin (or use the Etherscan "Verify and Publish" page), paste your Etherscan API key, choose Sepolia and verify each address.
   - For `SafeBank`, use "flattened" or "standard JSON input" verification because it has an import.
6. In the app, choose **Sepolia Testnet**, paste each address and click **Analyze contract**.

Record the four addresses here and in the README so reviewers can try them:

| Contract | Sepolia address |
|---|---|
| VulnerableBank | |
| UnprotectedVault | |
| CentralizedToken | |
| SafeBank | |

> These contracts are deliberately vulnerable. Never send real funds to them.
