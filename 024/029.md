Raspy Gunmetal Urchin

medium

# Wrong rounding direction when queueing ETH withdrawal from operators

## Summary
Wrong rounding direction might try to withdrawal more assets than are available and revert.

## Vulnerability Detail
In the Operator Operations contract when the protocol tries to queue ETH withdrawal from operators for user settlement, the `amount` [is divided](https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/utils/OperatorOperations.sol#L88-L89) by the `ETH_DEPOSIT_SIZE` of 32eth, and then rounded up, to receive a value that represents the [number of operators](https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTOperatorRegistry.sol#L548) from which a withdrawal of 32eth will be deallocated and requested.

```solidity
        uint256 remainingDeposits = depositsToDeallocate;
```

The issue is that since it rounds up, if, for example there are 5 operators each with 32eth, and the rounded up number returned is 6, this will attempt to withdrawal from more operators than exist. It will cause a revert and throw the whole function
## Impact
Function can revert due to rounding up instead of down.

## Code Snippet
https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/utils/OperatorOperations.sol#L88-L89

https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTOperatorRegistry.sol#L548

## Tool used
Manual Review

## Recommendation
Instead of rounding up, opt to round down, this way a revert can never happen.