Sweet Navy Dragonfly

medium

# Unallocated assets may largely reduce the profit belongs to the user whose funds are utilized

## Summary
Unallocated assets may largely reduce the profit belongs to the user whose funds are utilized.

## Vulnerability Detail
When user deposits to Rio, LRT tokens are first [minted to user](https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/restaking/RioLRTCoordinator.sol#L84-L85) to the user, and when rebalancing, [allocateStrategyShares(...)](https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/restaking/RioLRTOperatorRegistry.sol#L342) function is called to allocate shares to the operators.If the allocation of the operator with the lowest utilization rate is maxed out, function exits earlier and no more shares will be allocated.
```solidity
            if (operatorShares.allocation >= operatorShares.cap) break;
```
The unallocated assets are not returned to user but stay in the deposit pool. This is problematic because the rewards protocol gains from Eigenlayer are shared by the LRT holders, given LRT tokens are also minted for the unallocated assets, User's profit can be largely reduced.

## Impact
User's profit is largely reduced.

## Code Snippet
https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/restaking/RioLRTOperatorRegistry.sol#L342

## Tool used

Manual Review

## Recommendation
Return funds back to user if reaches the cap, and only mint LRT tokens to users whose funds are utilized.