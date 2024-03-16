Merry Wintergreen Rook

medium

# ChainLink's 'latestRoundData' might return stale or incorrect result

## Summary 

It's so common that developers tend to make this mistake of not checking the return data properly from chainlink while using the latestRoundData() function. This sometimes leads to unexpected behaviour.

## Vulnerability Detail

On ChainlinkPriceFeed.sol , we are using latestRoundData, but there is no check if the return value indicates stale data.

https://docs.chain.link/docs/faq/#how-can-i-check-if-the-answer-to-a-round-is-being-carried-over-from-a-previous-round
https://docs.chain.link/docs/historical-price-data/#historical-rounds

## Impact

This could lead to stale prices according to the Chainlink documentation and leads to unexpected behaviour.

## Code Snippet

https://github.com/sherlock-audit/2024-02-rio-vesting-core-protocol/blob/main/rio-sherlock-audit/contracts/oracle/ChainlinkPriceFeed.sol#L35

```solidity
function getPrice() external view returns (uint256) {
        (, int256 price,, uint256 updatedAt,) = IChainlinkAggregatorV3(source).latestRoundData();
        if (block.timestamp > updatedAt + stalePriceDelay) revert STALE_PRICE();
        if (price <= 0) revert BAD_PRICE();

        return uint256(price);
    }
```

## Tool used

Manual Review

## Recommendation

```solidity
function getPrice() external view returns (uint256) {

(uint80 roundID, int256 answer, , uint256 updatedAt, uint80 answeredInRound) = IChainlinkAggregatorV3(source).latestRoundData();

        require(answeredInRound >= roundID, "Stale price");
        require(answer > 0," Error.NEGATIVE_PRICE");
        require(block.timestamp <= updatedAt + stalePriceDelay, Error.STALE_PRICE);

        return uint256(answer);
}
```