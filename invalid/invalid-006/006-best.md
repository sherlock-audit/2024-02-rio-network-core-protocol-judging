Quaint Peach Swan

medium

# Unhandled ChainLink revert would lock price oracle access causing DoS.

## Summary

The call to `ChainlinkPriceFeed::latestRoundData` function could potentially revert and make it impossible to query any prices. This could lead to permanent denial of service.

## Vulnerability Detail

Call to [latestRoundData](https://github.com/sherlock-audit/2024-02-rio-vesting-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/oracle/ChainlinkPriceFeed.sol#L35) could potentially revert and make it impossible to query any prices. Feeds cannot be changed after they are configured so this would result in a permanent denial of service.

## Impact

Chainlink's multisigs can immediately block access to price feeds at will. Therefore, to prevent denial of service scenarios, it is recommended to query Chainlink price feeds using a defensive approach with Solidity’s try/catch structure. In this way, if the call to the price feed fails, the caller contract is still in control and can handle any errors safely and explicitly.

Refer to this blog by [OpenZeppelin](https://blog.openzeppelin.com/secure-smart-contract-guidelines-the-dangers-of-price-oracles/) for more information regarding potential risks to account for when relying on external price feed providers.

## Code Snippet

```solidity
    function getPrice() external view returns (uint256) {
        /// @audit - Unhandled Oracle Revert Denial Of Service
        (, int256 price,, uint256 updatedAt,) = IChainlinkAggregatorV3(source).latestRoundData();
        if (block.timestamp > updatedAt + stalePriceDelay) revert STALE_PRICE();
        if (price <= 0) revert BAD_PRICE();

        return uint256(price);
    }
```
https://github.com/sherlock-audit/2024-02-rio-vesting-core-protocol/blob/main/rio-sherlock-audit/contracts/oracle/ChainlinkPriceFeed.sol#L35

## Tool used

Manual Review

## Recommendation

Surround the call to `latestRoundData()` with `try/catch` statements instead of calling it directly. In a scenario where the call reverts, the catch block can be used to call a fallback oracle or handle the error in any other suitable way.
