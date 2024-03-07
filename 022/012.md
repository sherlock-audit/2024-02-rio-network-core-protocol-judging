Wide Laurel Skunk

high

# OperatorRegistryV1Admin::getOperatorUtilizationHeapForETH():Wrong accounting of heap.count

## Summary
There is wrong accounting of Data::count in getOperatorUtilizationHeapForETH().
## Vulnerability Detail
The struct `Data` represents the heap :
https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/utils/OperatorUtilizationHeap.sol#L40-L44 where `count` denotes the number of element the heap contains.
See the following code:
https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/utils/OperatorRegistryV1Admin.sol#L369-L385
In this Unchecked block the `count` is updated like this:
Assume `numActiveOperator` = 4.
So, inside `for` loop:
i = 0 ->  operators[i+1] => operators[0+1] => operators[1]
i = 1 ->  operators[i+1] => operators[1+1] => operators[2]
i = 2 ->  operators[i+1] => operators[2+1] => operators[3]
i = 3 ->  operators[i+1] => operators[3+1] => operators[4]
After the execution of `for` loop the length of the Data.operators is 4 and as `heap.count=i` so heap.count will be 3 because now `i`'s value is 3.
The problem will arise when we go to store the heap into storage by calling [store()](https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/utils/OperatorUtilizationHeap.sol#L68).
Take the previous assumption where `numActiveOperator`=4, so we know the `count` will be 3.
Lets implement the loop logic of store():
i = 0 -> set(operators[i+1]) => operator[1]
i = 1 -> set(operators[1+1]) => operator[2]
i = 2 -> set(operators[2+1]) => operator[3]
That's all. As `i < self.count` condition will not satisfy on further loop, so this the execution will be stopped. As we can see the last operator in operators[ ] was not stored in storage, we lost 1 operator i.e last operator.
There are more issue resulted from the miscalculation, let's see all one by one:

### 1. [OperatorUtilizationHeap::remove()](https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/utils/OperatorUtilizationHeap.sol#L94)
Assume there are 4 operator in operators[ ], last operator's index is 4 because ROOT_INDEX = 1. As operators.length is 4 so count will be 3.
Suppose this function was called to remove the last operator i.e index 4. The condition need to passed:
```solidity
 if (index < ROOT_INDEX || index > self.count) revert INVALID_INDEX();
```
But this condition check will fail because index is 4 and `index > self.count`. So the operator will not be removed from the heap.

### 2. [OperatorUtilizationHeap::updateUtilization()](https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/utils/OperatorUtilizationHeap.sol#L116)
Same as remove(). The condition `if (index < ROOT_INDEX || index > self.count) revert INVALID_INDEX();` will fails if user wanna update the utilization of last operator.

### 3. [OperatorUtilizationHeap::extractMax()](https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/utils/OperatorUtilizationHeap.sol#L152)
Assume `count` is 1, that means we have 2 operator in operators[ ]. So in this `if` statement:
```solidity
        // If the heap only contains one element, it's both the min and max.
        if (self.count == 1) {
            return self.operators[self.count--];
        }
```
If count ==1 then count-- will be evaluated as index of max. So in this case we have count == 1 but count-- will be 0. As ROOT_INDEX = 1 we don't have any operator at operators[0].
Now see the another snippet of this function:
```solidity
        if (self.count >= 3 && self.operators[3].utilization > self.operators[2].utilization) {
            maxIndex = 3;
        }
        o = self.operators[maxIndex];
```
Assume there are 4 operators in operators[ ], so count will be 3 & also assume that `self.operators[3].utilization > self.operators[2].utilization`. So as per this logic `maxIndex` will be 3 because count == 3. But we know maxIndex is 4, not 3. 

### 4. [OperatorUtilizationHeap::getMax()](https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/utils/OperatorUtilizationHeap.sol#L181)
Assume count == 2, so operators.length will be 3 means there are 3 operators in operators[ ].
See the snippet:
```solidity
        uint8 maxIndex = 2;
        if (self.count >= 3 && self.operators[3].utilization > self.operators[2].utilization) {
            maxIndex = 3;
        }
        return self.operators[maxIndex];
```
If count == 2 then this `if` statement will evaluate to false so maxIndex will be 2 as per the snippet logic. But actual maxIndex should be 3. So 2nd operator will be returned but the 3rd operator should be returned.

### 5. [OperatorUtilizationHeap::getMaxIndex()](https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/utils/OperatorUtilizationHeap.sol#L199)
Same as 4.



> **N.B:** _The `heap.count` is correctly maintained by calling [`insert()`](https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/utils/OperatorUtilizationHeap.sol#L80), but this function was only used in [`allocateETHDeposit()`](https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/restaking/RioLRTOperatorRegistry.sol#L397) [to reinsert operators](https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/restaking/RioLRTOperatorRegistry.sol#L471) in heap which was [extracted from heap by calling `extractMin()`](https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/restaking/RioLRTOperatorRegistry.sol#L433)._

## Impact
See the Vulnerability details section.
## Code Snippet
https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/utils/OperatorRegistryV1Admin.sol#L357-L386
## Tool used

Manual Review

## Recommendation
Change this line: 
https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/utils/OperatorRegistryV1Admin.sol#L384 to `heap.count = i + 1;`.