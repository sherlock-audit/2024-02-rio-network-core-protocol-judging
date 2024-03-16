Attractive Dijon Hornet

medium

# `validatorKeyReviewPeriod` will not be applied correctly by `operatorManager` in `addValidatorDetails`.

## Summary
after validators submit their own public keys and signatures, operatorManager review keys and batch update their state to confirmed.
However even if current timestamp does not reach `nextConfirmationTimestamp`, it will be updated by adding `validatorKeyReviewPeriod`.
It may result in more waiting period to validators.

## Vulnerability Detail
Assume that current timestamp is 10s before nextConfirmationTimestamp and operatorManager calls addValidatorDetails method.
timestamp does not reach nextConfirmationTimestamp (it will reach in 10 seconds.), so pending validators can't be updated to confirmed but nextConfirmationTimestamp.
```solidity
 function addValidatorDetails(
        uint8 operatorId,
        uint256 validatorCount,
        bytes calldata publicKeys,
        bytes calldata signatures
    ) external onlyOperatorManager(operatorId) {
        OperatorDetails storage operator = s.operatorDetails[operatorId];
        OperatorValidatorDetails memory validators = operator.validatorDetails;

        if (validatorCount == 0) revert INVALID_VALIDATOR_COUNT();

        // First check if there are any pending validator details that can be moved into a confirmed state.
@>      if (validators.total > validators.confirmed && block.timestamp >= validators.nextConfirmationTimestamp) {
@>          operator.validatorDetails.confirmed = validators.confirmed = validators.total;
@>      }

        operator.validatorDetails.total = VALIDATOR_DETAILS_POSITION.saveValidatorDetails(
            operatorId, validators.total, validatorCount, publicKeys, signatures
        );
@>      operator.validatorDetails.nextConfirmationTimestamp = uint40(block.timestamp + s.validatorKeyReviewPeriod); 

        emit OperatorPendingValidatorDetailsAdded(operatorId, validatorCount);
    }
```

Therefore validators should wait s.ValidatorKeyReviewPeriod more (nearly twice period = 2 days after added into storage).
In worst case, add another validators again before nextConfirmationTimestamp, then it will be delayed more again. 


## Impact
validatorKeyReviewPeriod may be delayed longer than expected.

## Code Snippet
https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/restaking/RioLRTOperatorRegistry.sol#L273-L275
https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/restaking/RioLRTOperatorRegistry.sol#L280

## Tool used

Manual Review

## Recommendation
Store confirmation timestamp for each validator and check if nextConfirmationTimestamp has been reached for each validator.