Quaint Peach Swan

medium

# PriceOracle will use the wrong price if the Chainlink registry returns price outside a predefined range.

## Summary

Chainlink aggregators have a built in circuit breaker if the price of an asset goes outside of a predetermined price band. The result is that if an asset experiences a huge drop in value (i.e. LUNA crash) the price of the oracle will continue to return the `minPrice` instead of the actual price of the asset. This would allow user to continue borrowing with the asset but at the wrong price. This is exactly what happened to [Venus on BSC when LUNA imploded](https://rekt.news/venus-blizz-rekt/).

## Vulnerability Detail

The `ChainlinkPriceFeed::latestRoundData` function pulls the associated aggregator and requests round data from it. ChainlinkAggregators have minPrice and maxPrice circuit breakers built into them. This means that if the price of the asset drops below the minPrice or goes above the maxPrice, the protocol will continue to value the token at minPrice/maxPrice instead of its actual value.

Example:
- TokenA has a minPrice of $1.
- The price of TokenA drops to $0.10.
- The aggregator still returns $1 allowing the user to borrow against TokenA as if it is $1 which is 10x its actual value.

With current implementation, there is only a check for price to be non-negative, but not within an acceptable range.

## Impact

The wrong price may be returned in the event of a market crash. An adversary will then be able to cause catastrophic damage to the protocol.

## Code Snippet

```solidity
function getPrice() external view returns (uint256) {
        (, int256 price,, uint256 updatedAt,) = IChainlinkAggregatorV3(source).latestRoundData();
        if (block.timestamp > updatedAt + stalePriceDelay) revert STALE_PRICE();
        /// @audit use the proper range of minPrice and maxPrice for each asset
        if (price <= 0) revert BAD_PRICE();
        return uint256(price);
    }
```

https://github.com/sherlock-audit/2024-02-rio-vesting-core-protocol/blob/main/rio-sherlock-audit/contracts/oracle/ChainlinkPriceFeed.sol#L35-#L37

## Tool used

Manual Review

## Recommendation

ChainlinkPriceFeed contract should check the returned price against both the minPrice and maxPrice and revert if the price is outside of the bounds.


```diff
function getPrice() external view returns (uint256) {
        (, int256 price,, uint256 updatedAt,) = IChainlinkAggregatorV3(source).latestRoundData();
        if (block.timestamp > updatedAt + stalePriceDelay) revert STALE_PRICE();
+        if (price <= minPrice && price >= maxPrice) revert BAD_PRICE();
-        if (price <= 0) revert BAD_PRICE();
        return uint256(price);
    }
```