Deep Daisy Cricket

high

# Missing access control in `addOperator()` in OperatorRegistryV1Admin library

## Summary
Only owner should `add operators` to the system but anyone can add operators as it lacks `access control` in `OperatorRegistryV1Admin` library

## Vulnerability Detail
Operators are added through `RioLRTOperatorRegistry::addOperator()` which uses a library `OperatorRegistryV1Admin` to add operators, `RioLRTOperatorRegistry::addOperator()` has `onlyOwner` modifier but the library `OperatorRegistryV1Admin::addOperator()` don't have, and its a external function
```solidity
  function addOperator(
        RioLRTOperatorRegistryStorageV1.StorageV1 storage s,
        address token,
        address operatorDelegatorBeacon,
        IRioLRTOperatorRegistry.OperatorConfig memory config
 @>   ) external returns (uint8 operatorId, address delegator) {
         /// code......
    }
```

## Impact
Malicious operators can be added, also they can maliciously reach the `MAX_OPERATOR_COUNT` and `MAX_ACTIVE_OPERATOR_COUNT` preventing honest operators getting added

## Code Snippet
https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/utils/OperatorRegistryV1Admin.sol#L39

https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/restaking/RioLRTOperatorRegistry.sol#L135

## Tool used
Manual Review

## Recommendation
Use modifier that allows onlyOperatorRegistry to call `OperatorRegistryV1Admin::addOperator()`