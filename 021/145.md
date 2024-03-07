Strong Denim Hyena

medium

# Active AVSs can get their Slashing/Registry contracts unexpectedly deactivated

## Summary
The AVS Registry expects each AVS to use a unique slashing and registry contract. When deactivating an AVS, its corresponding slashing contract is also deactivated. However, other active AVSs that use the same slashing contract will also have their slashing contract deactivated.

## Vulnerability Detail
Whenever an AVS is added or activated, its corresponding slashing and registry contracts are also activated.

ref: https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/restaking/RioLRTAVSRegistry.sol#L60-L99
```solidity
function addAVS(string calldata name, address slashingContract, address registryContract) external onlyOwner returns (uint128 avsId) {
    // ... snip ...
    if (slashingContract != address(0)) {
        _isActiveSlashingContract[slashingContract] = true;
    }
    _isActiveRegistryContract[registryContract] = true;

    emit AVSAdded(avsId, name, slashingContract, registryContract);
}

function activateAVS(uint128 avsId) external onlyOwner {
    // ... snip ...
    if (avs.slashingContract != address(0)) {
        _isActiveSlashingContract[avs.slashingContract] = true;
    }
    _isActiveRegistryContract[avs.registryContract] = true;

    emit AVSActivated(avsId);
}
```

When an AVS is deactivated, its corresponding slashing and registry contracts are deactivated. 
ref: https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/restaking/RioLRTAVSRegistry.sol#L104-L118
```solidity
function deactivateAVS(uint128 avsId) external onlyOwner {
    // ... snip ...
    if (avs.slashingContract != address(0)) {
        _isActiveSlashingContract[avs.slashingContract] = false;
    }
    _isActiveRegistryContract[avs.registryContract] = false;

    emit AVSDeactivated(avsId);
}
```

Note, however, that the above code also deactivates the registry and slashing contracts of AVSs that share the same contracts, even if those AVSs are still active. This implicit assumption unexpectedly deactivates slashing and registry contracts of active AVSs.

Note that Eigenlayer has designs, although not final, to use a singleton Slasher contract. There are also no guarantees in the Eigenlayer protocol that each AVS will have a unique Slashing contract. Considering this, it would be prudent to remove assumptions in the code that slashing and/or registry contracts are all unique to their own AVS.

## Impact
Other active AVSs will have their corresponding Slashing/Registry contracts unexpectedly set to deactivated.

## Code Snippet
- https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/restaking/RioLRTAVSRegistry.sol#L60-L99
- https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/restaking/RioLRTAVSRegistry.sol#L104-L118

## Tool used

Manual Review

## Recommendation
Consider supporting share slashing and/or registry contracts for AVSs to mitigate the issue. A possible way to do this is to change `_isActiveSlashingContract` and `_isActiveRegistryContract` to an `address => uint` mapping to support multiple AVSs using the same slashing and/or registry contracts. When adding or activating an AVS, record the use of the slashing and registry contracts in the mapping by incrementing its value by 1. When deactivating an AVS, do the opposite by decrementing the mappings by 1.

The `isActiveSlashingContract` function can then be changed to:
```solidity
function isActiveSlashingContract(address slashingContract) external view returns (bool) {
    return _isActiveSlashingContract[slashingContract] > 0;
}
```

The `isActiveRegistryContract` function can be changed to:
```solidity
function isActiveRegistryContract(address registryContract) external view returns (bool) {
    return _isActiveRegistryContract[registryContract] > 0;
}
```
