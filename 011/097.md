Obedient Carbon Leopard

medium

# Withdrawn operator can stake ETH back in EigenPod manipulating shares

## Summary
When Ether is deposited through EigenPod, each validator can receive up to 32 ETH in the operator's validators. Each 32 ETH deposit is allocated to a separate validator. However, when a full withdrawal occurs due to either a user withdrawal or operator exit, the withdrawn validator cannot receive deposits again, necessitating the addition of new validator keys. Nevertheless, these previous validators may still have staked Ether outside of the system, and their ETH deposits can be withdrawn to increase withdrawableRestakedExecutionLayerGwei, thereby blocking the scraping of excess ETH in user full withdrawals.

## Vulnerability Detail
When a new validator set defined to an operator delegators contract the new deposits can go through to those validators as follows:
   ```solidity
 function allocateETHDeposits(uint256 depositsToAllocate) external onlyDepositPool returns (uint256 depositsAllocated, OperatorETHAllocation[] memory allocations) {
        .
        while (remainingDeposits > 0 && !heap.isEmpty()) {
            uint8 operatorId = heap.getMin().id;
            .
            OperatorDetails storage operator = s.operatorDetails[operatorId];
            OperatorValidatorDetails memory validators = operator.validatorDetails;
            -> uint256 activeDeposits = validators.deposited - validators.exited;


            // If the current deposited validator count of the operator is greater than or equal to its cap,
            // then exit early. We will not be able to allocate to any other operators.
            if (activeDeposits >= validators.cap) break;
            .
            .
           .

                // Load the allocated validator details from storage and update the deposited validator count.
                (pubKeyBatch, signatureBatch) = ValidatorDetails.allocateMemory(newDepositAllocation);
                -> VALIDATOR_DETAILS_POSITION.loadValidatorDetails(
                    operatorId, validators.deposited, newDepositAllocation, pubKeyBatch, signatureBatch, 0
                );
                -> operator.validatorDetails.deposited += uint40(newDepositAllocation);
                .
            }
            .
        }
        .
        .
     }
}
```

as we can see above snippet, if an operator has 5 validator keys from which only 3 of them has deposits, then the deposited is 3 and the next potential 2*32 ether can be deposited to the validator 4th and 5th. 

Now, when a validator exits this is how the deallocation from validators work:
```solidity
function deallocateETHDeposits(uint256 depositsToDeallocate) external onlyCoordinator returns (uint256 depositsDeallocated, OperatorETHDeallocation[] memory deallocations) {
        .
        bytes memory pubKeyBatch;
        while (remainingDeposits > 0) {
            uint8 operatorId = heap.getMax().id;


            OperatorDetails storage operator = s.operatorDetails[operatorId];
            OperatorValidatorDetails memory validators = operator.validatorDetails;
            -> uint256 activeDeposits = validators.deposited - validators.exited;

            // Exit early if the operator with the highest utilization rate has no active deposits,
            // as no further deallocations can be made.
            if (activeDeposits == 0) break;


            // Each deallocation will trigger the withdrawal of a 32 ETH deposit. The specific validators
            // to withdraw from are chosen by the software run by the operator.
            uint256 newDepositDeallocation = FixedPointMathLib.min(activeDeposits, remainingDeposits);
            pubKeyBatch = ValidatorDetails.allocateMemoryForPubKeys(newDepositDeallocation);
            -> VALIDATOR_DETAILS_POSITION.loadValidatorDetails(
                operatorId, validators.exited, newDepositDeallocation, pubKeyBatch, new bytes(0), 0
            );
            -> operator.validatorDetails.exited += uint40(newDepositDeallocation);
            .
        }
        .
        }
    }
```

as we can see above, if the operator has 5 validators and all of it has deposits which would mean deposited is 5. Hence, there can be 5*32 ether can be withdrawn from the operator delegators eigen pod. If the 2*32 ether is requested, then the exited will be 2 and deposited is still 5. Which means, the next time eth is deallocated the validator 3rd-4th and 5th can be requested from withdrawal. Also, after a withdrawal, if the operator can allocate more ETH the new keys required since from the 2 above snippet we can see that the validator that will do the deposit will be the validator at queue:
```solidity
VALIDATOR_DETAILS_POSITION.loadValidatorDetails(
                    operatorId, validators.deposited, newDepositAllocation, pubKeyBatch, signatureBatch, 0
                );
```
hence, a previously withdrawn (exited) validator can not have a new ether deposit. A new key is required. 

Now, when a validator withdraws from the EigenPod as we can see its status is set to WITHDRAWN here:
https://github.com/Layr-Labs/eigenlayer-contracts/blob/6de01c6c16d6df44af15f0b06809dc160eac0ebf/src/contracts/pods/EigenPod.sol#L700-L701

However, technically a WITHDRAWN validator can still have deposits but it can not prove to get more EigenPod shares because the verifyBalanceUpdates and verifyWithdrawalCredentials functions in EigenPod will revert due to validator not being INACTIVE.

Though, the malicious operator can deposit some ether to its validator back again and then calls `verifyAndProcessWithdrawals`. Since EigenPod accepts WITHDRAWN validators to withdraw, this function will increase `withdrawableRestakedExecutionLayerGwei` in the EigenPod contract. 

So, assuming the operator delegator has 5 validators which 3 of them exited and 2 is active, that means there are 64 ether in eigen pod shares. If the malicious operator re-deposits 32 to one of the WITHDRWAN validotor and calls `verifyAndProcessWithdrawals` then the `withdrawableRestakedExecutionLayerGwei` will be equal to 32 ether. Though, the TVL in rio will not change since it does not account the `withdrawableRestakedExecutionLayerGwei` variable. 

The problem is, now, scraping the excess ETH from EigenPod can be impossible. 

Assume some user request a withdrawal of 34 ether which since the operator has 2 validators actively deposited in EigenPod, it will do a full withdrawal of 64 ether and 64-34 = 30 ether will be scrapeable after settling the user withdrawal epoch. 

When the 64 ether is fully withdrawn the `withdrawableRestakedExecutionLayerGwei` will be increased by an another 64 ether which will be now 64+32 = 96 ether

when user claims the withdrawal after a successful complete eth withdrawal then the `withdrawableRestakedExecutionLayerGwei` will decrease 34 ether which will be 96-34 = 62 ether

32 of this 62 ether is the malicious operators ether deposit and the other 30 ether is the Rio LRT's depositors claim which should be scraped back normally. However, as we can see in below code snippet, it is impossible to scrape this amount because to scrape amount will be calculated as 62 ether but the delegator only has 30 eigen pod shares. 

```solidity
function scrapeExcessFullWithdrawalETHFromEigenPod() external {
        uint256 ethWithdrawable = eigenPod.withdrawableRestakedExecutionLayerGwei().toWei();
        uint256 ethQueuedForWithdrawal = getETHQueuedForWithdrawal();
        if (ethWithdrawable <= ethQueuedForWithdrawal + MIN_EXCESS_FULL_WITHDRAWAL_ETH_FOR_SCRAPE) {
            revert INSUFFICIENT_EXCESS_FULL_WITHDRAWAL_ETH();
        }
        _queueWithdrawalForOperatorExitOrScrape(BEACON_CHAIN_STRATEGY, ethWithdrawable - ethQueuedForWithdrawal);
    }
```

Conclusively, the 30 ether will be stuck.
 
## Impact
Ether will stuck in the EigenPod contract. The operator has to deposit 32 ether intentionally or unintentionally to an exited validator to perform this attack vector which would make the severity medium imo.
## Code Snippet
https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTOperatorRegistry.sol#L397-L481

https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTOperatorRegistry.sol#L541-L594

https://github.com/Layr-Labs/eigenlayer-contracts/blob/6de01c6c16d6df44af15f0b06809dc160eac0ebf/src/contracts/pods/EigenPod.sol#L232-L277

https://github.com/Layr-Labs/eigenlayer-contracts/blob/6de01c6c16d6df44af15f0b06809dc160eac0ebf/src/contracts/pods/EigenPod.sol#L294-L345

https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTOperatorDelegator.sol#L160-L167
## Tool used

Manual Review

## Recommendation
