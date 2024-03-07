Obedient Carbon Leopard

high

# Heap is incorrectly stores the removed operator ID which can lead to division by zero in deposit/withdrawal flow

## Summary
An operator's strategy can be reset by the owner calling `setOperatorStrategyCaps` to "0". This action sets the utilization to "0" and removes the operator from the heap. Consequently, this means that the operator has unwound all its strategy shares and can no longer receive any more deposits. However, due to how the heap is organized, if an operator who had funds before is reset to "0", the heap will not successfully remove the operator. As a result, when ordering the heap, a division by "0" will occur, causing the transaction to revert on deposits and withdrawals indefinitely.
## Vulnerability Detail
In order to break down the issue, let's divide the issue to 2 parts which their combination is the issue itself

**1- Heap is not removing the removed ID from the heaps storage when the operator is removed**

When the operator is removed, the operator will be removed from the heap as follows:
```solidity
function setOperatorStrategyCap(
        RioLRTOperatorRegistryStorageV1.StorageV1 storage s,
        uint8 operatorId,
        IRioLRTOperatorRegistry.StrategyShareCap memory newShareCap
    ) internal {
        .
        OperatorUtilizationHeap.Data memory utilizationHeap = s.getOperatorUtilizationHeapForStrategy(newShareCap.strategy);
        // If the current cap is greater than 0 and the new cap is 0, remove the operator from the strategy.
        if (currentShareDetails.cap > 0 && newShareCap.cap == 0) {
            // If the operator has allocations, queue them for exit.
            if (currentShareDetails.allocation > 0) {
                operatorDetails.queueOperatorStrategyExit(operatorId, newShareCap.strategy);
            }
            // Remove the operator from the utilization heap.
            -> utilizationHeap.removeByID(operatorId);
        }
        .

        // Persist the updated heap to the active operators tracking.
        -> utilizationHeap.store(s.activeOperatorsByStrategyShareUtilization[newShareCap.strategy]);
         .
    }
```

`removeByID` calls the internal `_remove` function which is **NOT** removes the last element! `self.count` is decreased however, the index is still the previous value of the `self.count`
```solidity
function _remove(Data memory self, uint8 i) internal pure {
        self.operators[i] = self.operators[self.count--];
    }
```

**For example, if there are 3 operators as follows:**
operatorId: 1, utilization: 50%
operatorId: 2, utilization: 60%
operatorId: 3, utilization: 70%
then, the `heap.count` would be 3
and the order would be: 1, 2, 3 in the heap
heap.operators[1] = operatorId 1
heap.operators[2] = operatorId 2
heap.operators[3] = operatorId 3

**if we remove the operator Id 2:**
`heap.count` = 2
order: 1,3
heap.operators[1] = operatorId 1
heap.operators[2] = operatorId 2
**heap.operators[3] = operatorId 0**  THIS SHOULD BE "0" since its removed but it is "3" in the current implementation!

As shown here, the operators[3] should be "0" since there isn't any operator3 in the heap anymore but the heap keeps the value and not resets it. 

**Here a test shows the above issue:**
```solidity
// forge test --match-contract OperatorUtilizationHeapTest --match-test test_removingDoesNotUpdatesStoredHeap -vv
    function test_removingDoesNotUpdatesStoredHeap() public {
        OperatorUtilizationHeap.Data memory heap = OperatorUtilizationHeap.initialize(5);

        heap.insert(OperatorUtilizationHeap.Operator({id: 1, utilization: 50}));
        heap.store(heapStore);

        heap.insert(OperatorUtilizationHeap.Operator({id: 2, utilization: 60}));
        heap.store(heapStore);

        heap.insert(OperatorUtilizationHeap.Operator({id: 3, utilization: 70}));
        heap.store(heapStore);

        console.log("Heaps count", heap.count);
        console.log("1st", heap.operators[1].id);
        console.log("2nd", heap.operators[2].id);
        console.log("3rd", heap.operators[3].id);

        // remove 2
        heap.removeByID(3);
        heap.store(heapStore);

        console.log("Heaps count", heap.count);
        console.log("1st", heap.operators[1].id);
        console.log("2nd", heap.operators[2].id);
        console.log("3rd", heap.operators[3].id);
    }
```
**Logs:**
<img width="563" alt="image" src="https://github.com/sherlock-audit/2024-02-rio-vesting-core-protocol-mstpr/assets/120012681/72ce2e8c-dd74-4e77-9bd7-f1096923165e">


**2- When the operator cap is reseted the allocations/deallocations will not work due to above heap issue because of division by zero**

Now, take the above example, we removed the operatorId 3 from the heap by setting its cap to "0". Now, there are only operators 1 and 2 active for that specific strategy.
When there are idle funds in the deposit pool before the rebalance call, the excess funds that are not requested as withdrawals will be pushed to EigenLayer as follows:
```solidity
function rebalance(address asset) external checkRebalanceDelayMet(asset) {
       .
       .
        -> (uint256 sharesReceived, bool isDepositCapped) = depositPool().depositBalanceIntoEigenLayer(asset);
        .
    }
```
```solidity
 function depositBalanceIntoEigenLayer(address asset) external onlyCoordinator returns (uint256, bool) {
        uint256 amountToDeposit = asset.getSelfBalance();
        if (amountToDeposit == 0) return (0, false);
        .
        .
        -> return (OperatorOperations.depositTokenToOperators(operatorRegistry(), asset, strategy, sharesToAllocate), isDepositCapped);
    }
```

```solidity
function depositTokenToOperators(
        IRioLRTOperatorRegistry operatorRegistry,
        address token,
        address strategy,
        uint256 sharesToAllocate
    ) internal returns (uint256 sharesReceived) {
       -> (uint256 sharesAllocated, IRioLRTOperatorRegistry.OperatorStrategyAllocation[] memory  allocations) = operatorRegistry.allocateStrategyShares(
            strategy, sharesToAllocate
        );
        .
        .
    }
```
```solidity
function allocateStrategyShares(address strategy, uint256 sharesToAllocate) external onlyDepositPool returns (uint256 sharesAllocated, OperatorStrategyAllocation[] memory allocations) {
        -> OperatorUtilizationHeap.Data memory heap = s.getOperatorUtilizationHeapForStrategy(strategy);
       .
       .
       .
       .
    }
```

```solidity
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
                heap.operators[i + 1] = OperatorUtilizationHeap.Operator({
                    id: operatorId,
                    -> utilization: operatorShares.allocation.divWad(operatorShares.cap)
                });
            }
            heap.count = i;
        }
    }
```
As we can see in one above code snippet, the `numActiveOperators` is 3. Since the stored heaps last element is not set to "0" it will point to operatorId 3 which has a cap of "0" after the removal. This will make the
```solidity
utilization: operatorShares.allocation.divWad(operatorShares.cap)
```
part of the code to perform a division by zero and the function will revert. 

**Coded PoC:**
```solidity
// forge test --match-contract RioLRTOperatorRegistryTest --match-test test_Capped0ValidatorBricksFlow -vv
    function test_Capped0ValidatorBricksFlow() public {
        // Add 3 operators
        addOperatorDelegators(reLST.operatorRegistry, address(reLST.rewardDistributor), 3);

        // The caps for each operator is 1000e18, we will delete the id 2 so we need funds there
        // any number that is more than 1000 should be ok for that experiement 
        uint256 AMOUNT = 1002e18;

        // Allocate to cbETH strategy.
        cbETH.approve(address(reLST.coordinator), type(uint256).max);
        uint256 lrtAmount = reLST.coordinator.deposit(CBETH_ADDRESS, AMOUNT);

        // Push funds into EigenLayer.
        vm.prank(EOA, EOA);
        reLST.coordinator.rebalance(CBETH_ADDRESS);

        // Build the empty caps
        IRioLRTOperatorRegistry.StrategyShareCap[] memory zeroStrategyShareCaps =
            new IRioLRTOperatorRegistry.StrategyShareCap[](1);
        zeroStrategyShareCaps[0] = IRioLRTOperatorRegistry.StrategyShareCap({strategy: CBETH_STRATEGY, cap: 0});

        // Set the caps of CBETH_STRATEGY for operator 2 as "0"
        reLST.operatorRegistry.setOperatorStrategyShareCaps(2, zeroStrategyShareCaps);

        // Try an another deposit, we expect revert when we do the rebalance
        reLST.coordinator.deposit(CBETH_ADDRESS, 10e18);

        // Push funds into EigenLayer. Expect revert, due to division by "0"
        skip(reETH.coordinator.rebalanceDelay());
        vm.startPrank(EOA, EOA);
        vm.expectRevert(bytes4(keccak256("DivWadFailed()")));
        reLST.coordinator.rebalance(CBETH_ADDRESS);
        vm.stopPrank();
    }
```
## Impact
Core logic broken, withdrawal/deposits can not be performed. 
## Code Snippet
https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/utils/OperatorRegistryV1Admin.sol#L231C5-L270C6

https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/utils/OperatorUtilizationHeap.sol#L94-L110

https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTCoordinator.sol#L121-L151

https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTDepositPool.sol#L47-L67

https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/utils/OperatorOperations.sol#L51-L68

https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTOperatorRegistry.sol#L342-L392

https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/utils/OperatorRegistryV1Admin.sol#L327-L351
## Tool used

Manual Review

## Recommendation
When removing from the heap also remove the last element from the heap.

**I am not sure of this, but this might work**
```solidity
function _remove(Data memory self, uint8 i) internal pure {
        self.operators[i] = self.operators[--self.count];
    }
```