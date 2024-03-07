Dazzling Syrup Rat

medium

# Missing __gap in upgradeable contract

## Summary

For upgradeable contracts, there must be storage gap to "allow developers to freely add new state variables in the future without compromising the storage compatibility with existing deployments" (quote from OpenZeppelin). Otherwise it may be very difficult to write new implementation code. Without storage gap, the variable in child contract might be overwritten by the upgraded base contract if new variables are added to the base contract. This could have unintended and very serious consequences to the child contracts.

## Vulnerability Detail

Major Protocol contract are intended to be upgradeable contracts in the code base. However, the inherited contract doesnt contain any storage gap. The storage gap is essential for upgradeable contract to avoid storage collision when adding new state vars.

## Impact

The absence of storage gaps in upgradeable contracts can result in storage collisions, presenting potential risks to the contract's functionality.

## Code Snippet
The [RioLRTCore abstract contract](https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/restaking/base/RioLRTCore.sol)

Will be used in: 

[RioLRTAVSRegistry](https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/restaking/RioLRTAVSRegistry.sol#L9)

[RioLRTAssetRegistry](https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/restaking/RioLRTAssetRegistry.sol#L15)

[RioLRTCoordinator](https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/restaking/RioLRTCoordinator.sol#L17)

[RioLRTDepositPool](https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/restaking/RioLRTDepositPool.sol#L21)

[RioLRTOperatorDelegator](https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/restaking/RioLRTOperatorDelegator.sol#L25)

[RioLRTOperatorRegistry](https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTOperatorRegistry.sol#L23C10-L23C32)

[RioLRTRewardDistributor](https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/restaking/RioLRTRewardDistributor.sol#L10)

[RioLRTWithdrawalQueue](https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/restaking/RioLRTWithdrawalQueue.sol#L16)
 

## Tool used

Manual Review

## Recommendation

Recommend adding appropriate storage gap at the end of upgradeable contracts such as the below. Please reference OpenZeppelin upgradeable contract templates.

uint256[50] private __gap;