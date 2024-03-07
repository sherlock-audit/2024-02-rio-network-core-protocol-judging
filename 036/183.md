Bald Vanilla Eagle

medium

# When `validatorCount` is greater than or equal to `fromIndex`, the function `reportOutOfOrderValidatorExits` will fail.

## Summary

When `validatorCount` is greater than or equal to `fromIndex`, the function `reportOutOfOrderValidatorExits` will fail.

## Vulnerability Detail

In the function `reportOutOfOrderValidatorExits`, it will swap the position of the validators starting from the `fromIndex` with the validators that were next in line to be exited. However, when validators.exited is 0 and  `validatorCount` is greater than or equal to `fromIndex`, function `swapValidatorDetails` will be reverted due to INDEXES_OVERLAP.

## POC

I modified the test function `test_reportOutOfOrderValidatorExits` as shown below.

```solidity
function test_reportOutOfOrderValidatorExits() public {
    uint40 UPLOADED_KEY_COUNT = 1_000;

    uint256 DEPOSIT_COUNT = 300;
    uint256 OOO_EXIT_STARTING_INDEX = 100;
    uint256 OOO_EXIT_COUNT = 100;

    uint8 operatorId = addOperatorDelegator(
        reETH.operatorRegistry, address(reETH.rewardDistributor), emptyStrategyShareCaps, UPLOADED_KEY_COUNT
    );

    IRioLRTOperatorRegistry.OperatorPublicDetails memory details =
        reETH.operatorRegistry.getOperatorDetails(operatorId);

    // Allocate `DEPOSIT_COUNT` deposits
    vm.prank(address(reETH.depositPool));
    reETH.operatorRegistry.allocateETHDeposits(DEPOSIT_COUNT);

    // Mark operators as withdrawn.
    vm.mockCall(
        address(IRioLRTOperatorDelegator(details.delegator).eigenPod()),
        abi.encodeWithSelector(IEigenPod.validatorStatus.selector),
        abi.encode(IEigenPod.VALIDATOR_STATUS.WITHDRAWN)
    );

    // Ensure the expected public keys are swapped.
    uint256 j = OOO_EXIT_STARTING_INDEX;
    (bytes memory expectedPublicKeys,) = TestUtils.getValidatorKeys(UPLOADED_KEY_COUNT);
    for (uint256 i = 0; i < OOO_EXIT_COUNT; i++) {
        uint256 key1Start = j * ValidatorDetails.PUBKEY_LENGTH;
        uint256 key1End = (j + 1) * ValidatorDetails.PUBKEY_LENGTH;

        uint256 key2Start = i * ValidatorDetails.PUBKEY_LENGTH;
        uint256 key2End = (i + 1) * ValidatorDetails.PUBKEY_LENGTH;

        vm.expectEmit(true, false, false, true, address(reETH.operatorRegistry));
        emit ValidatorDetails.ValidatorDetailsSwapped(
            operatorId,
            bytes(LibString.slice(string(expectedPublicKeys), key1Start, key1End)),
            bytes(LibString.slice(string(expectedPublicKeys), key2Start, key2End))
        );

        j++;
    }

    // Report the out of order exits of `OOO_EXIT_COUNT` validators starting at index `OOO_EXIT_STARTING_INDEX`.
    reETH.operatorRegistry.reportOutOfOrderValidatorExits(operatorId, OOO_EXIT_STARTING_INDEX, OOO_EXIT_COUNT);

    details = reETH.operatorRegistry.getOperatorDetails(operatorId);
    assertEq(details.validatorDetails.exited, OOO_EXIT_COUNT);
}
```

Finally, the execution results are as follows:

![swapError](https://github.com/sherlock-audit/2024-02-rio-vesting-core-protocol-zrax-x/assets/52646245/ff5bf14f-e99c-430a-adba-3791af59926e)


## Impact

The function reportOutOfOrderValidatorExits can’t work normally.

## Code Snippet

https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/restaking/RioLRTOperatorRegistry.sol#L310-L336

https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/utils/ValidatorDetails.sol#L129-L130

## Tool used

Manual Review

## Recommendation

Modify the overlap check logic.