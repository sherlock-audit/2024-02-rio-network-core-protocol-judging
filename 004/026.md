Strong Denim Hyena

medium

# Inaccurate ETH TVL impacts shares minting and rewards allocation

## Summary
The TVL calculation of the assets held by LRT is incorrect when one of the assets is ether and the unit of account is USD. ETH value is bloated which leads to more restaking tokens getting minted when ETH is used for deposits. This leads to a significantly greater proportion of the rewards getting allocated to ETH depositors.

## Vulnerability Detail
The total TVL of all assets held by the LRT is used for converting asset tokens to restaking tokens and vice-versa during deposits and withdrawals.

ref: https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/restaking/RioLRTAssetRegistry.sol#L69-L83
```solidity
    /// @notice Returns the total value of all underlying assets in the unit of account.
    function getTVL() public view returns (uint256 value) {
        address[] memory assets = getSupportedAssets();
        for (uint256 i = 0; i < assets.length; ++i) {
            value += getTVLForAsset(assets[i]);
        }
    }

    /// @notice Returns the total value of the underlying asset in the unit of account.
    /// @param asset The address of the asset.
    function getTVLForAsset(address asset) public view returns (uint256) {
        uint256 balance = getTotalBalanceForAsset(asset);
        if (asset == ETH_ADDRESS) {
            return balance;
        }
        return convertToUnitOfAccountFromAsset(asset, balance);
    }
```

When getting the TVL for the LRT, we get the sum of the TVL in each supported asset. The TVL is expressed in the Unit of Account which has a precision of either 8 or 18 decimals. This works fine for most assets except ETH.

ref: https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/restaking/RioLRTAssetRegistry.sol#L184-L196
```solidity
  function convertToUnitOfAccountFromAsset(address asset, uint256 amount) public view returns (uint256) {
      if (asset == ETH_ADDRESS) {
          return amount;  // @audit-issue the assumption is that the UoA is ETHER. However, this is not always the case
      }
      // price feed - 8; asset - 18; priceScale - 1e8
      address priceFeed = assetInfo[asset].priceFeed;
      uint256 price = getPrice(priceFeed);

      // @audit can lead to loss of precision since price feed is 8 decimals for non-ETH pairs.
      return _normalizeDecimals(price * amount / priceScale, assetInfo[asset].decimals, priceFeedDecimals);
  }
```

The conversion above is used when getting the TVL of an asset. The issue is that, in the case of Ether as the asset, the returned amount is not converted to the unit of account and is always in 18-decimal precision. When the LRT's unit of account is USD, it will be in 8-decimals precision. This leads to bloating of the value of ETH by roughly 7 decimals (given a price of ~3000 USD per ETH). 

## Impact
 Any inaccuracy in an asset TVL will either bloat or shrink the value of the shares during deposit and withdrawal. In this case, ETH value is bloated which leads to more restaking tokens getting minted when ETH is used for deposits. In effect, ETH depositors will get a greater portion of the yield than the depositors of other assets even when they deposit the same value.

## Code Snippet
- https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/restaking/RioLRTCoordinator.sol#L79
- https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/restaking/RioLRTCoordinator.sol#L219
- https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/restaking/RioLRTCoordinator.sol#L101
- https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/restaking/RioLRTCoordinator.sol#L162-L183
- https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/restaking/RioLRTAssetRegistry.sol#L69-L83
- https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/restaking/RioLRTAssetRegistry.sol#L184-L196

## Tool used
Manual Review

## Recommendation
Consider converting ETH to the unit of account (like USD in 8-decimal precision) when the unit of account is non-ETH. Below is rough code that shows the possible fix:

```diff
diff --git a/rio-sherlock-audit/contracts/restaking/RioLRTAssetRegistry.sol b/rio-sherlock-audit/contracts/restaking/RioLRTAssetRegistry.sol
index 6e35373..798bf97 100644
--- a/rio-sherlock-audit/contracts/restaking/RioLRTAssetRegistry.sol
+++ b/rio-sherlock-audit/contracts/restaking/RioLRTAssetRegistry.sol
@@ -186,7 +186,7 @@ contract RioLRTAssetRegistry is IRioLRTAssetRegistry, OwnableUpgradeable, UUPSUp
     /// @param asset The address of the asset to convert.
     /// @param amount The amount of the asset to convert.
     function convertToUnitOfAccountFromAsset(address asset, uint256 amount) public view returns (uint256) {
-        if (asset == ETH_ADDRESS) {
+        if (asset == ETH_ADDRESS && priceFeedDecimals == 18) {
             return amount;
         }
         address priceFeed = assetInfo[asset].priceFeed;
@@ -200,7 +200,7 @@ contract RioLRTAssetRegistry is IRioLRTAssetRegistry, OwnableUpgradeable, UUPSUp
     /// @param asset The address of the asset to convert to.
     /// @param value The asset's value in the unit of account.
     function convertFromUnitOfAccountToAsset(address asset, uint256 value) public view returns (uint256) {
-        if (asset == ETH_ADDRESS) {
+        if (asset == ETH_ADDRESS && priceFeedDecimals == 18) {
             return value;
         }
         address priceFeed = assetInfo[asset].priceFeed;
@@ -329,7 +329,10 @@ contract RioLRTAssetRegistry is IRioLRTAssetRegistry, OwnableUpgradeable, UUPSUp
 
         uint8 decimals = config.asset == ETH_ADDRESS ? 18 : IERC20Metadata(config.asset).decimals();
         if (config.asset == ETH_ADDRESS) {
-            if (config.priceFeed != address(0)) revert INVALID_PRICE_FEED();
+            // when the LRT price feed has 18 decimals, the unit of account is ETH and no asset price feed has to be set
+            if (priceFeedDecimals == 18 && config.priceFeed != address(0)) revert INVALID_PRICE_FEED();
+            // when the LRT price feed has 8 decimals, the unit of account is USD and an asset price feed has to be set
+            if (priceFeedDecimals == 8 && config.priceFeed == address(0)) revert INVALID_PRICE_FEED();
             if (config.strategy != BEACON_CHAIN_STRATEGY) revert INVALID_STRATEGY();
         } else {
             if (decimals > 18) revert INVALID_ASSET_DECIMALS();
```