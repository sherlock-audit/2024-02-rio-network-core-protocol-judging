Powerful Pastel Albatross

high

# `activeOperatorCount` could exceed `MAX_ACTIVE_OPERATOR_COUNT` and it would freeze the protocol.

kennedy1030

high

## Summary

Because there is no upper bound checking in `OperatorRegistryV1Admin.activateOperator()`, `activeOperatorCount` can exceed `MAX_ACTIVE_OPERATOR_COUNT`.
This happens when `activateOperator()` is called in the case of `activeOperatorCount == MAX_ACTIVE_OPERATOR_COUNT`.

## Vulnerability Detail

There is no upper bound checking in `OperatorRegistryV1Admin.activateOperator()`.

https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/utils/OperatorRegistryV1Admin.sol#L95

```javascript
    function activateOperator(RioLRTOperatorRegistryStorageV1.StorageV1 storage s, uint8 operatorId) external {
        IRioLRTOperatorRegistry.OperatorDetails storage operator = s.operatorDetails[operatorId];

        if (operator.delegator == address(0)) revert IRioLRTOperatorRegistry.INVALID_OPERATOR_DELEGATOR();
        if (operator.active) revert IRioLRTOperatorRegistry.OPERATOR_ALREADY_ACTIVE();

        operator.active = true;
        s.activeOperatorCount += 1;

        emit IRioLRTOperatorRegistry.OperatorActivated(operatorId);
    }

```
Suppose that `activateOperator()` is called in the case of `activeOperatorCount == MAX_ACTIVE_OPERATOR_COUNT`.  Because there is no upper bound checking in `OperatorRegistryV1Admin.activateOperator()`, `activeOperatorCount` will be set as  `MAX_ACTIVE_OPERATOR_COUNT + 1`.
Now `activeOperatorCount` > `MAX_ACTIVE_OPERATOR_COUNT`. So, `OperatorRegistryV1Admin.getOperatorUtilizationHeapForStrategy()` will be reverted by array range overflow at `OperatorRegistryV1Admin.sol#L345`. As a result, `deactivateOperator()` is also reverted and even owner cannot fix it. Because `rebalance()` is reverted, main stream of protocol will never run any more. In `RioLRTCoordinator.sol`, `deposit()` and `requestWithdrawl()` can be done, but they will only increase the loss, because `rebalance()` is reverted.

https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/utils/OperatorRegistryV1Admin.sol#L328

```javascript
    function getOperatorUtilizationHeapForStrategy(RioLRTOperatorRegistryStorageV1.StorageV1 storage s, address strategy) internal view returns (OperatorUtilizationHeap.Data memory heap) {
        uint8 numActiveOperators = s.activeOperatorCount;
        if (numActiveOperators == 0) return OperatorUtilizationHeap.Data(new OperatorUtilizationHeap.Operator[](0), 0);
        
        heap = OperatorUtilizationHeap.initialize(MAX_ACTIVE_OPERATOR_COUNT);
        LibMap.Uint8Map storage operators = s.activeOperatorsByStrategyShareUtilization[strategy];

        IRioLRTOperatorRegistry.OperatorShareDetails memory operatorShares;
        unchecked {
            uint8 i;
            for (i = 0; i < numActiveOperators; ++i) {
                uint8 operatorId = operators.get(i);

                // Non-existent operator ID. We've reached the end of the heap.
                if (operatorId == 0) break;

                operatorShares = s.operatorDetails[operatorId].shareDetails[strategy];
345             heap.operators[i + 1] = OperatorUtilizationHeap.Operator({
                    id: operatorId,
                    utilization: operatorShares.allocation.divWad(operatorShares.cap)
                });
            }
            heap.count = i;
        }
    }
```

## Impact

All important actions of protocol will be reverted. Thus, the protocol cannot work any more.

## Code Snippet

https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/utils/OperatorRegistryV1Admin.sol#L95
https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/utils/OperatorRegistryV1Admin.sol#L328

## Tool used

Manual Review

## Recommendation

https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/utils/OperatorRegistryV1Admin.sol#L95

```diff
    function activateOperator(RioLRTOperatorRegistryStorageV1.StorageV1 storage s, uint8 operatorId) external {
        IRioLRTOperatorRegistry.OperatorDetails storage operator = s.operatorDetails[operatorId];

        if (operator.delegator == address(0)) revert IRioLRTOperatorRegistry.INVALID_OPERATOR_DELEGATOR();
        if (operator.active) revert IRioLRTOperatorRegistry.OPERATOR_ALREADY_ACTIVE();
+       if (s.activeOperatorCount >= MAX_ACTIVE_OPERATOR_COUNT) {
+           revert IRioLRTOperatorRegistry.MAX_ACTIVE_OPERATOR_COUNT_EXCEEDED();
+       }
        operator.active = true;
        s.activeOperatorCount += 1;

        emit IRioLRTOperatorRegistry.OperatorActivated(operatorId);
    }

```