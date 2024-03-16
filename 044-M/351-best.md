Radiant Amethyst Haddock

medium

# Potential Revert in `allocateStrategyShares` Function would prevent EigenLayer deposits

## Summary

The `allocateStrategyShares` function might revert if the heap becomes empty before allocating all the provided shares, temporarily preventing deposits to EigenLayer.

## Vulnerability Detail

When depositing tokens (excluding ETH) from the pool balance into EigenLayer via the `depositBalanceIntoEigenLayer` function, the `depositTokenToOperators` function is called to manage operator allocation and staking into EigenLayer. We'll focus on the operator shares allocation handled by the `allocateStrategyShares` function.

Operators are stored in a heap structure organized by their respective utilization rates. When `allocateStrategyShares` begins allocating shares, it iterates over this heap, traversing operators with the lowest utilization rate until all shares are allocated.

The `allocateStrategyShares` function uses a while loop to iterate over operators, continuing until there are no more shares to allocate (`remainingShares == 0`).

The potential issue arises if, after allocating shares to all operators in the heap and reaching their respective caps, there are still shares to allocate (`remainingShares > 0`). In this scenario, the loop continues, and if the heap becomes empty, `heap.getMin()` will revert due to the following check:

```solidity
function getMin(Data memory self) internal pure returns (Operator memory) {
    if (self.isEmpty()) revert HEAP_UNDERFLOW();

    return self.operators[ROOT_INDEX];
}
```

This issue can occur even with the check on operator caps in the `allocateStrategyShares` function:

```solidity
if (operatorShares.allocation >= operatorShares.cap) break;
```

This check won't trigger if the last operator in the heap isn't at maximum capacity. After allocating to this operator, the loop runs again and reverts because the heap is empty.

This situation temporarily prevents the protocol from depositing funds into EigenLayer until new operators are added to cover the remaining shares, resulting in potential loss as the assets could have been generating yield in EigenLayer instead of waiting in the deposit pool.

A common scenario for this issue is during the initial deposit when there are few operators:

- The deposit pool has DAI funds to deposit into EigenLayer (first-time deposit).
- There are currently four registered operators, none with any allocation yet.
- When `allocateStrategyShares` is called, it allocates the maximum shares to each operator, but some shares remain. The loop attempts to fetch another operator from the heap but reverts as the heap is empty after allocating to the four operators.
- The revert prevents funds from depositing into EigenLayer, causing the entire rebalance call (where `depositBalanceIntoEigenLayer` is invoked) to revert. Consequently, funds remain in the deposit pool without generating yield until new operators are added.

## Impact

The `allocateStrategyShares` function might revert if the heap becomes empty before allocating all provided shares, temporarily preventing deposits to EigenLayer.

## Code Snippet

https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/restaking/RioLRTOperatorRegistry.sol#L342-L392

## Tool used

Manual Review

## Recommendation

To address this issue, modify the `allocateStrategyShares` function to break its while loop when the operator heap is empty:

```solidity
function allocateStrategyShares(address strategy, uint256 sharesToAllocate) external onlyDepositPool returns (uint256 sharesAllocated, OperatorStrategyAllocation[] memory allocations) {
    OperatorUtilizationHeap.Data memory heap = s.getOperatorUtilizationHeapForStrategy(strategy);
    if (heap.isEmpty()) {
        return (sharesAllocated, allocations);
    }

    uint256 allocationIndex;
    uint256 remainingShares = sharesToAllocate;

    allocations = new OperatorStrategyAllocation[](s.activeOperatorCount);
    //@audit stop the loop if heap is empty
    while (remainingShares > 0 && !heap.isEmpty()) {
        ...
    }
    sharesAllocated = sharesToAllocate - remainingShares;

    heap.store(s.activeOperatorsByStrategyShareUtilization[strategy]);

    // Shrink the array length to the number of allocations made.
    if (allocationIndex < s.activeOperatorCount) {
        assembly {
            mstore(allocations, allocationIndex)
        }
    }
}
```
