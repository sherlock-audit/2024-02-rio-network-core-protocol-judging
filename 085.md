Active Azure Elephant

high

# Incorrect OperatorUtilizationHeap bubbleDown logic may result in DoS of allocate/deallocate logic

## Summary

OperatorUtilizationHeap bubbleDown logic has a critical flaw which results in the min-max heap not properly returning the min/max values as expected. The result of incorrect min/max values may be an inability to allocate/deallocate ETH deposits and strategy shares.

## Vulnerability Detail

OperatorUtilizationHeap is a min-max heap used to output the min/max utilized operators as used in allocation/deallocation in RioLRTOperatorRegistry. Min-max heaps work by alternating between min and max levels wherein we can bubble elements up or down such that the top min and max levels contain the min and max values respectively which can be retrieved in constant time.

The flaw in OperatorUtilizationHeap is in the `_bubbleDownMin` and `_bubbleDownMax` functions. Looking at `_bubbleDownMin`, we can see that if the smallest child or grandchild is a grandchild and the grandchild is smaller than the provided index, we swap the grandchild and provided index and later recursively call `_bubbleDownMin` with the previous grandchild index.

```solidity
if (self._hasChildren(i)) {
uint8 m = self._getSmallestChildIndexOrGrandchild(i);
if (_isGrandchild(i, m)) {
    if (self.operators[m].utilization < self.operators[i].utilization) {
        self._swap(m, i);
        uint8 parentOfM = m / 2;
        if (self.operators[m].utilization > self.operators[parentOfM].utilization) {
            self._swap(m, parentOfM);
        }
        self._bubbleDownMin(m);
```

In general this flow makes sense as if the grandchild is smaller, we must swap it so that the larger value is transferred down the heap because the min value should be at the top of the min levels. However, in the case that the provided index is larger than its new parent, it gets swapped. The problem with this circumstance is that now `m` has been swapped to a max level and we are now recursively executing bubbleDownMin logic on a max level. This likely scrambles most of the heap such that values are incorrectly placed. 

What should actually be done in this circumstance is that instead of recursively calling `self._bubbleDownMin(m)`, we should be calling `self._bubbleDown(m)`, which will then determine the level the index is on and call the correct bubble down function accordingly.

## Impact

The OperatorUtilizationHeap is used to determine which operator should be allocated/deallocated to/from next according to its utilization. Since this flaw causes the heap to return incorrect min/max values, we will allocate/deallocate in an unintended order. Furthermore, we stop allocating/deallocating if the min/max operator allocation is full/empty respectively, if the min/max value is incorrect then later operators in the heap will not be able to be allocated/deallocated to/from, causing unexpected limits on deposits and an inability to withdraw fully.

## Code Snippet

- https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/utils/OperatorUtilizationHeap.sol#L241
- https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/utils/OperatorUtilizationHeap.sol#L265

## Tool used

Manual Review

## Recommendation

Instead of recursively calling `self._bubbleDownMin/Max(m)`, call `self._bubbleDown(m)`.