Strong Denim Hyena

medium

# Assets that did not gain yield are assumed to have yield on withdrawal

## Summary
During withdrawal processing, all non-ETH assets withdrawn are computed using the Eigenlayer strategy's exchange rate. This assumes that all assets have been deposited into the Eigenlayer strategy and have been gaining yield. However, this is not always the case since some assets can be in the Deposit Pool for an extended period.

## Vulnerability Detail
Assets in the Deposit Pool do not generate yield. However, when withdrawals are processed during rebalancing, the assets in the Deposit Pool are converted to shares using its corresponding Eigenlayer Strategy exchange rate. 

ref: https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/restaking/RioLRTDepositPool.sol#L76-L109
```solidity
function transferMaxAssetsForShares(address asset, uint256 sharesRequested, address recipient)
    external
    onlyCoordinator
    returns (uint256, uint256)
{
    uint256 poolBalance = asset.getSelfBalance();
    // converts pool balance to Eigenlayer shares even though balance is not deposited into Eigenlayer
    uint256 poolBalanceShareValue = assetRegistry().convertToSharesFromAsset(asset, poolBalance);
    // ... snip ...
}
```

ref: https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/restaking/RioLRTAssetRegistry.sol#L215-L221
```solidity
function convertToSharesFromAsset(address asset, uint256 amount) public view returns (uint256 shares) {
    // ... snip ...
    shares = IStrategy(strategy).underlyingToSharesView(amount);
}
```

This becomes an issue when the assets have stayed in the Deposit Pool for an extended period, since the assets do not gain yield. This can happen when the LRT's operators' strategy allocations are maxed out and the assets are left in the Deposit Pool.

ref: https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/restaking/RioLRTOperatorRegistry.sol#L358-L360
```solidity
function allocateStrategyShares(address strategy, uint256 sharesToAllocate) external onlyDepositPool returns (uint256 sharesAllocated, OperatorStrategyAllocation[] memory allocations) {
    // ... snip ...
    while (remainingShares > 0) {
        uint8 operatorId = heap.getMin().id;

        OperatorDetails storage operator = s.operatorDetails[operatorId];
        OperatorShareDetails memory operatorShares = operator.shareDetails[strategy];

        // If the allocation of the operator with the lowest utilization rate is maxed out,
        // then exit early. We will not be able to allocate to any other operators.
        if (operatorShares.allocation >= operatorShares.cap) break;
        // ... snip ...
    }
}
```

Consider the following scenario:
- 50% of the assets (like cbETH) held by the LRT are stuck in the Deposit Pool since allocations are already maxed out or the Strategy is already at its deposit cap.
- The assets in the Deposit Pool have remained there for 1 month and multiple rebalancing cycles.
- After 1 month, the Strategy exchange rate has increased by 10%.
- Depositors attempt to withdraw all the cbETH in the LRT.

The above scenario will result in insolvency because not all depositors will be able to redeem their shares and recover all their assets/principal in cbETH. The issue lies in the conversion of the Deposit Pool assets into shares using the Strategy exchange rate which has already increased by 10%. The Deposit Pool's assets did not benefit from any Strategy yield but they are assumed to have gained yield on withdrawal.

## Impact
Not all depositors will be able to withdraw their assets/principal for non-ETH assets.

## Code Snippet
- https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/restaking/RioLRTAssetRegistry.sol#L215-L221
- https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/restaking/RioLRTOperatorRegistry.sol#L358-L360
- https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/restaking/RioLRTDepositPool.sol#L76-L109
- https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/restaking/RioLRTCoordinator.sol#L247
- https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/restaking/RioLRTCoordinator.sol#L128
- https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/restaking/RioLRTCoordinator.sol#L121-L151
- https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/restaking/RioLRTDepositPool.sol#L66

## Tool used

Manual Review

## Recommendation
Consider using a different exchange rate when computing for assets withdrawn during rebalancing. This exchange rate should take into account the percentage of assets that are in the Deposit Pool and the percentage that is in the Eigenlayer strategy.
