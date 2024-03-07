Cool Aquamarine Unicorn

medium

# PriceFeed decimals check not implemented on `setAssetPriceFeed`

## Summary
`RioLRTAssetRegistry::setAssetPriceFeed` function to set a new price feed for an asset does not check if the new price feed decimals is equal to the `priceFeedDecimals` variable on the contract, which could lead to miscalculations.

## Vulnerability Detail
`RioLRTAssetRegistry` has the capability to add assets and set their `IRioLRTAssetRegistry::AssetInfo` on the `addAsset` function which then calls inside the `_addAsset` function:
```solidity
    /// @notice Adds a new underlying asset to the liquid restaking token.
    /// @param config The asset's configuration.
    function addAsset(AssetConfig calldata config) external onlyOwner {
        _addAsset(config);
    }
    ...
    /// @dev Adds a new underlying asset to the liquid restaking token.
    /// @param config The asset's configuration.
    function _addAsset(AssetConfig calldata config) internal {
        if (isSupportedAsset(config.asset)) revert ASSET_ALREADY_SUPPORTED(config.asset);
        if (config.asset == address(0)) revert INVALID_ASSET_ADDRESS();

        uint8 decimals = config.asset == ETH_ADDRESS ? 18 : IERC20Metadata(config.asset).decimals();
        if (config.asset == ETH_ADDRESS) {
            if (config.priceFeed != address(0)) revert INVALID_PRICE_FEED();
            if (config.strategy != BEACON_CHAIN_STRATEGY) revert INVALID_STRATEGY();
        } else {
            if (decimals > 18) revert INVALID_ASSET_DECIMALS();
            if (config.priceFeed == address(0)) revert INVALID_PRICE_FEED();
            if (IPriceFeed(config.priceFeed).decimals() != priceFeedDecimals) revert INVALID_PRICE_FEED_DECIMALS();
            if (IStrategy(config.strategy).underlyingToken() != config.asset) revert INVALID_STRATEGY();
        }
        supportedAssets.push(config.asset);
  
        AssetInfo storage info = assetInfo[config.asset];
        info.decimals = decimals;
        info.depositCap = config.depositCap;
        info.priceFeed = config.priceFeed;
        info.strategy = config.strategy;
  
        emit AssetAdded(config);
    }
```

In the `_addAsset` function there is the following check,
`if (IPriceFeed(config.priceFeed).decimals() != priceFeedDecimals) revert INVALID_PRICE_FEED_DECIMALS();`, only allowing price feeds with a stablished decimals amount to facilitate calculations. Any discrepancy between the expected price feed decimals with the actual price feed decimals will result in under or overpricing assets.

The issue is that in `setAssetPriceFeed`, when updating the price feed of an asset, that previously mentioned check is never done which may produce a discrepancy if the new price feed does not have the same amount of decimals required by the `RioLRTAssetRegistry` contract.

Imagine the following scenario:
- A Chainlink price feed is taken offline and a new one is added for the same asset.
- The new price feed has a bigger number for decimals (lets say that before it was 8 and now 10).
- A new user comes and deposits 1e18 of that asset (lets say that's one unit of the asset).
- The market value of the asset is $10, so the new price feed returns 10e10 as price.
- The system was expecting to receive the price feed data with only 8 decimals so calculations result in the system valuating user's assets as $1000.
- User receives x100 more reETH for those overpriced assets.
## Impact
In the case of the new price feed decimals being bigger than before, user could get `10**delta`more reETH minted than expected. However, if the delta is negative, meaning that the new price feed decimals number is less than before user would get a smaller amount of reETH than expected. 

## Code Snippet
https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTAssetRegistry.sol#L242-L246
https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTAssetRegistry.sol#L324-L349
https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTAssetRegistry.sol#L275-L284

Add the following test to `test/RioLRTAssetRegistry.t.sol`:

```solidity
    function test_setAssetPriceFeedWithInvalidDecimals() public {
        // Creating a new price feed to change the old one
        MockPriceFeed newFeed = new MockPriceFeed(1e18);
        newFeed.setDecimals(8);

        address oldPriceFeed = reLST.assetRegistry.getAssetPriceFeed(RETH_ADDRESS);
        uint256 oldPriceFeedDecimals = MockPriceFeed(oldPriceFeed).decimals();

        // Using RETH because is already deployed and well setted by test suite
        reLST.assetRegistry.setAssetPriceFeed(RETH_ADDRESS, address(newFeed));

        address newPriceFeed = reLST.assetRegistry.getAssetPriceFeed(RETH_ADDRESS);
        uint256 newPriceFeedDecimals = MockPriceFeed(newPriceFeed).decimals();

        assert(oldPriceFeedDecimals != newPriceFeedDecimals);
    }
```

## Tool used

Manual Review

## Recommendation
Add the decimals check on the `RioLRTAssetRegistry::setAssetRegistry` function:

```diff
/// @dev Sets the asset's price feed.
/// @param newPriceFeed The new price feed.
function setAssetPriceFeed(address asset, address newPriceFeed) external onlyOwner {
    if (!isSupportedAsset(asset)) revert ASSET_NOT_SUPPORTED(asset);
    if (newPriceFeed == address(0)) revert INVALID_PRICE_FEED();
+   if (IPriceFeed(newPriceFeed).decimals() != priceFeedDecimals) revert INVALID_PRICE_FEED_DECIMALS();
 
	assetInfo[asset].priceFeed = newPriceFeed;

    emit AssetPriceFeedSet(asset, newPriceFeed);
}
```
