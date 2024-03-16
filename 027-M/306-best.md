Rough Golden Dog

high

# `RioLRTOperatorRegistry:activateOperator` does not properly update info to the storage

## Summary

`RioLRTOperatorRegistry:activateOperator` does not properly update the activated operator information to the storage.
In the worst case, (if the activation is followed by deactivating the last operator), it is not recoverable and no more rebalance is possible. Potentially bricking the restaking contract resulting in majority of fund freeze.


## Vulnerability Detail

The full code for proof of concept can be found here: https://gist.github.com/lemonmon1984/5aca3c4cb0c48a520d4462bb8d10a8df

```solidity
    function test_activateOperator_poc() public {
        // add 3 operators
        addOperatorDelegators(
            reETH.operatorRegistry,
            address(reETH.rewardDistributor),
            3);
        // operator [] for active, cap 1 for non-zero
        // operator: [1 2 3] 0 0 0 
        // cap:       1 1 1  0 0 0 

        uint8 operatorId = 1;

        reETH.operatorRegistry.deactivateOperator(operatorId);
        // operator: [2 3] 3 0 0 0 
        // cap:       1 1  1  0 0 0

        // it is a problem to just increase the count
        // without adding operator 1 into the storage
        reETH.operatorRegistry.activateOperator(operatorId);
        // operator: [2 3 3] 0 0 0 
        // cap:       1 1 1  0 0 0
        
        // @audit: Even though one cannot reactivate the operator 1
        // at this point via setOperatorValidatorCap with non-zero cap,
        // it is possible recover from this state by deactivate the operator 1
        // reETH.operatorRegistry.setOperatorValidatorCap(operatorId, 3);

        // @audit: but it seems like it is not recoverable
        // if a mistake of deactivating the wrong operator (the last one)
        reETH.operatorRegistry.deactivateOperator(3);
        // operator: [2 3] 3 0 0 0 
        // cap:       1 0  0  0 0 0
        // the 3 is deactivated but it will be included in the heap
        // that will cause problem when allocation or deallocation is called

        IRioLRTOperatorRegistry.OperatorPublicDetails memory operatorDetails =
            reETH.operatorRegistry.getOperatorDetails(operatorId);
        assertEq(operatorDetails.active, true);
        assertEq(reETH.operatorRegistry.activeOperatorCount(), 2);

        reETH.coordinator.depositETH{value: ETH_DEPOSIT_SIZE}();

        uint24 initialRebalanceDelay = reETH.coordinator.rebalanceDelay();
        reETH.coordinator.setRebalanceDelay(initialRebalanceDelay - 1);

        // Skip forward using the new, slightly shorter delay.
        skip(reETH.coordinator.rebalanceDelay());

        vm.expectRevert(FixedPointMathLib.DivWadFailed.selector);
        vm.prank(EOA, EOA);
        reETH.coordinator.rebalance(ETH_ADDRESS);
    }
```

Here is step by step explanation of the above scenario:

1. initially 3 operator is added: Below is a schematic of `s.activeOperatorsByETHDepositUtilization`. And What is in `[...]` is what would be in the `heap = s.getOperatorUtilizationHeapForETH`. CAP is 1 for non-zero cap and 0 for zero cap.
```solidity
s.activeOperatorCount: 3
OPERATORID: [1 2 3] 0 0 0 ...
CAP:         1 1 1  0 0 0
```

2. Then the operatorId 1 was deactivated. It will shrink the heap and store it via ` s.setOperatorValidatorCap(operatorId, 0)`. Then it will decrease `s.activeOperatorCount` by 1. After this step the storage would be like below:
```solidity
// After operator 1 is deactivated
s.activeOperatorCount: 2
OPERATORID: [2 3] 3 0 0 0 ... // the last 3 is not cleared
CAP:         1 1  1 0 0 0
```

3. Then the operatorId 1 is activated again. It will increase the `s.activeOperatorCount`. But it will not touch the storage. After this step the storage is:
```solidity
// After operator 1 is activated again
s.activeOperatorCount: 3
OPERATORID: [2 3 3] 0 0 0 ... // two 3s will be in the heap
CAP:         1 1 1  0 0 0
```

Note that at this point if allocation or deallocation is called, it might behave unexpected way, as the operator 3 is in the heap twice.
It seems like it might be recovered if `deactivateOperator` is called on the operator 1 again.

However, if a wrong operator (operator 3) is deactivated after this, it is not recoverable and no more functionality involving allocation of deallocation is possible. Basically, rebalance cannot be done, which means no more deposit nor withdrawal is possible, as in the next step will demonstrate.

4. The last operator (id 3) is deactivated. After this step the storage will be:
```solidity
// After operator 3 is deactivated
s.activeOperatorCount: 2
OPERATORID: [2 3] 3 0 0 0 ... 
CAP:         1 0  0 0 0 0     // note that the cap is zero
```

5. rebalance is called but reverts with `DivWadFailed` as zero cap operator 3 is still included in the heap.


## Impact

The contract is possibly bricked locking all funds.
Even though it is protected function and likelyhood of scenario is rather low, it is reported as high severity because the potential damage is huge.

## Code Snippet

https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/restaking/RioLRTOperatorRegistry.sol#L148

https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/utils/OperatorRegistryV1Admin.sol#L129-L134

https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/utils/OperatorRegistryV1Admin.sol#L101-L102


## Tool used

Manual Review

## Recommendation

Like in the `deactivateOperator`, the `s.setOperatorValidatorCap` or `s.setOperatorStrategyCap` should be called before `s.activeOperatorCount` is updated. 

