Attractive Dijon Hornet

medium

# An asset with less than 6 decimals can be added in `supportedAssets` due to missing related check.

## Summary
Protocol says that standard ERC20 tokens with no less than 6 decimals and no more than 18 decimals. 
However, the `_addAsset` function only checks whether an asset has more than 18 decimal places, but not more than 6 decimal places.

## Vulnerability Detail
Only checks if decimals is no more than 18, but not checks if decimals is no less than 6.

## Impact
An asset which is not preferred by protocol can be added due to missing checks.

## Code Snippet
https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/restaking/RioLRTAssetRegistry.sol#L335

## Tool used

Manual Review

## Recommendation
```solidity
-   if (decimals > 18) revert INVALID_ASSET_DECIMALS();
-   if (decimals > 18 || decimals < 6) revert INVALID_ASSET_DECIMALS();
```