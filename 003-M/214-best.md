Tall Daffodil Octopus

medium

# Lack of slippage parameters can affect the LRT / share amounts during deposits / withdrawals

## Summary

During both deposits and withdrawals, the amount that the user receives in LRT tokens (during deposits) or amount of shares (during withdrawals) Is dependent on mainly the correlation between the supply of the given asset, the TVL (total value locked) and the price fetched from an oracle. 

Since the total value locked is dependent on the amount of shares recorded in the accounting system for the underlying asset in-question / all assets (updated during rebalances) + the balance of the assets in the contract (updated whenever the deposit is sent) this means that the value a user receives in return when depositing is dependent on the of the amount of shares + the current balance recorded in the protocol. 

During stepwise jumps in rewards accumulation and/or large deposits/withdrawals to/from the system, the TVL can drastically change, affecting the price ratio between the underlying assets and LRT. Users can get receive less LRT/shares than expected their deposit/withdrawal transaction was frontrun by a very large transaction, the protocol was rebalanced, etc.

## Vulnerability Detail

When deposits are made, the calculations for the amount of LRT tokens the user will get in return versus the number of shares is calculated by using the following formulas. Let's take a look at the deposit flow:

**Deposits:**

Once `amountOut` is calculated, this will determine the amount of LRT tokens that the user will receive in exchange for their deposit in the underlying token (for e.g. reETH, cbETH, etc.) 

`        amountOut = convertFromAssetToRestakingTokens(asset, amountIn);`

```solidity
  function convertFromAssetToRestakingTokens(address asset, uint256 amount) public view returns (uint256) {
        uint256 value = assetRegistry().convertToUnitOfAccountFromAsset(asset, amount);
        return convertFromUnitOfAccountToRestakingTokens(value);
    }
```
From the above the `value` parameter will be calculated by fetching the price from the price oracle: 

```solidity
function convertToUnitOfAccountFromAsset(address asset, uint256 amount) public view returns (uint256) {
        if (asset == ETH_ADDRESS) {
            return amount;
        }
        address priceFeed = assetInfo[asset].priceFeed;
        uint256 price = getPrice(priceFeed);

        return _normalizeDecimals(price * amount / priceScale, assetInfo[asset].decimals, priceFeedDecimals);
    }
```
After `value` is returned using the above calculations, then we will call the `convertFromUnitOfAccountToRestakingTokens()` with the `value` parameter as a function argument. This function will output the amount of LRT tokens that the user should receive based on the calculations below:

```solidity
function convertFromUnitOfAccountToRestakingTokens(uint256 value) public view returns (uint256) {
        uint256 tvl = getTVL();
        uint256 supply = token.totalSupply();

        if (supply == 0) {
            return value;
        }
        return value * supply / tvl;
    }
```
As we can see, the above function utilizes the TVL (Total Value Locked) in the protocol (of all underlying assets) to come up with the price. The TVL is greatly dependent on the amount of shares currently accounted for in the system: 

```solidity
function getTVLForAsset(address asset) public view returns (uint256) {
        uint256 balance = getTotalBalanceForAsset(asset);
        if (asset == ETH_ADDRESS) {
            return balance;
        }
        return convertToUnitOfAccountFromAsset(asset, balance);
```

The way that `balance` is calculated, since it's crucial for the TVL which is based on balance * oraclePriceForAsset; it takes into consideration all of the asset shares held in Rio: `assetInfo[asset].shares` + the `balanceOf(asset)`:

```solidity
  uint256 sharesHeld = getAssetSharesHeld(asset);
        uint256 tokensInRio = IERC20(asset).balanceOf(depositPool_);
        uint256 tokensInEigenLayer = convertFromSharesToAsset(getAssetStrategy(asset), sharesHeld);

        return tokensInRio + tokensInEigenLayer;
```

**PoC**
- For simpler calculations, let's say that Alice wants to deposit ETH through the `depositETH()` function:

```solidity
        // Convert deposited ETH to restaking tokens and mint to the caller.
        amountOut = convertFromUnitOfAccountToRestakingTokens(msg.value);

        // Forward ETH to the deposit pool.
        address(depositPool()).transferETH(msg.value);
```
- Alice wants to deposit 1 ETH (1e18), the current protocol TVL is 35e18, and the total supply of ETH is 12e25.
- To calculate the `amountOut`:
```solidity
 function convertFromUnitOfAccountToRestakingTokens(uint256 value) public view returns (uint256) {
        uint256 tvl = getTVL();
        uint256 supply = token.totalSupply();

        if (supply == 0) {
            return value;
        }
        return value * supply / tvl;
    }
```
- 1e18 * 12e25 / 1500e18.
- The amount of shares she will receive is 1.2e24
- If she was frontrun by a large transaction of let's say 200 ETH
- The amount would be: 1e18 * 12e25 / 1700e18 = 7e22.

## Impact

LRT tokens received in exchange for the underlying assets can vary and lead to unwanted outcomes due to the price dependency on the TVL as well as the amount of tokens received by the user is determined by an interaction with an oracle, meaning that the amount received in return may vary indefinitely while the request is waiting to be executed.
This is due to a lack of slippage control on any of the deposit / withdrawal functions. 

## Code Snippet
https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/restaking/RioLRTCoordinator.sol#L79

https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/restaking/RioLRTCoordinator.sol#L162-L169

https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/restaking/RioLRTCoordinator.sol#L219

## Tool used

Manual Review

## Recommendation

Include minimumOut parameters and maybe a deadline as well to enforce slippage control to the deposit/withdraw transactions in order to prevent unwanted outcomes.