Obedient Carbon Leopard

medium

# Ether can stuck when an operators validators are removed due to an user front-running

## Summary
When a full withdrawal occurs in the EigenPod, the excess amount can remain idle within the EigenPod and can only be swept by calling a function in the delegator contract of a specific operator. However, in cases where the owner removes all validators for emergencies or any other reason, a user can frontrun the transaction, willingly or not, causing the excess ETH to become stuck in the EigenPod. The only way to recover the ether would be for the owner to reactivate the validators, which may not be intended since the owner initially wanted to remove all the validators and now needs to add them again.
## Vulnerability Detail
Let's assume a Layered Relay Token (LRT) with a beacon chain strategy and only two operators for simplicity. Each operator is assigned two validators, allowing each operator to stake 64 ETH in the PoS staking via the EigenPod.

At any time, the EigenPod owner can update the effective balance of the validators' PoS staking by calling this function:
https://github.com/Layr-Labs/eigenlayer-contracts/blob/6de01c6c16d6df44af15f0b06809dc160eac0ebf/src/contracts/pods/EigenPod.sol#L294-L345
This function can be triggered by the owner of the operator registry or proof uploader by invoking this function:
https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTOperatorRegistry.sol#L236-L253

Now, let's consider a scenario where the effective verified balance of the most utilized operator is 64 ETH, and the operator's validators need to be shut down. In such a case, the operator registry admin can call this function to withdraw the entire ETH balance from the operator's delegator:
https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTOperatorRegistry.sol#L163-L165

This function triggers a full withdrawal from the operator's delegator EigenPod. The `queueOperatorStrategyExit` function will withdraw the entire validator balance as follows:
```solidity
if (validatorDetails.cap > 0 && newValidatorCap == 0) {
            // If there are active deposits, queue the operator for strategy exit.
            if (activeDeposits > 0) {
                -> operatorDetails.queueOperatorStrategyExit(operatorId, BEACON_CHAIN_STRATEGY);
                .
            }
           .
        } else if (validatorDetails.cap == 0 && newValidatorCap > 0) {
           .
        } else {
           .
        }
```

`operatorDetails.queueOperatorStrategyExit` function will full withdraw the entire validator balance as follows:

```solidity
function queueOperatorStrategyExit(IRioLRTOperatorRegistry.OperatorDetails storage operator, uint8 operatorId, address strategy) internal {
        IRioLRTOperatorDelegator delegator = IRioLRTOperatorDelegator(operator.delegator);

        uint256 sharesToExit;
        if (strategy == BEACON_CHAIN_STRATEGY) {
            // Queues an exit for verified validators only. Unverified validators must by exited once verified,
            // and ETH must be scraped into the deposit pool. Exits are rounded to the nearest Gwei. It is not
            // possible to exit ETH with precision less than 1 Gwei. We do not populate `sharesToExit` if the
            // Eigen Pod shares are not greater than 0.
            int256 eigenPodShares = delegator.getEigenPodShares();
            if (eigenPodShares > 0) {
                sharesToExit = uint256(eigenPodShares).reducePrecisionToGwei();
            }
        } else {
            .
        }
        .
    }
```
As observed, the entire EigenPod shares are requested as a withdrawal, which is 64 Ether. However, a user can request a 63 Ether withdrawal before the owner's transaction from the coordinator, which would also trigger a full withdrawal of 64 Ether. In the end, the user would receive 63 Ether, leaving 1 Ether idle in the EigenPod:
 
```solidity
function queueETHWithdrawalFromOperatorsForUserSettlement(IRioLRTOperatorRegistry operatorRegistry, uint256 amount) internal returns (bytes32 aggregateRoot) {
        .
        for (uint256 i = 0; i < length; ++i) {
            address delegator = operatorDepositDeallocations[i].delegator;

            -> // Ensure we do not send more than needed to the withdrawal queue. The remaining will stay in the Eigen Pod.
            uint256 amountToWithdraw = (i == length - 1) ? remainingAmount : operatorDepositDeallocations[i].deposits * ETH_DEPOSIT_SIZE;

            remainingAmount -= amountToWithdraw;
            roots[i] = IRioLRTOperatorDelegator(delegator).queueWithdrawalForUserSettlement(BEACON_CHAIN_STRATEGY, amountToWithdraw);
        }
        .
    }
```

In such a scenario, the queued amount would be 63 Ether, and 1 Ether would remain idle in the EigenPod. Since the owner's intention was to shut down the validators in the operator for good, that 1 Ether needs to be scraped as well. However, the owner is unable to sweep it due to `MIN_EXCESS_FULL_WITHDRAWAL_ETH_FOR_SCRAPE`:
```solidity
function scrapeExcessFullWithdrawalETHFromEigenPod() external {
        // @review this is 1 ether
        uint256 ethWithdrawable = eigenPod.withdrawableRestakedExecutionLayerGwei().toWei();
        // @review this is also 1 ether
        -> uint256 ethQueuedForWithdrawal = getETHQueuedForWithdrawal();
        if (ethWithdrawable <= ethQueuedForWithdrawal + MIN_EXCESS_FULL_WITHDRAWAL_ETH_FOR_SCRAPE) {
            revert INSUFFICIENT_EXCESS_FULL_WITHDRAWAL_ETH();
        }
        _queueWithdrawalForOperatorExitOrScrape(BEACON_CHAIN_STRATEGY, ethWithdrawable - ethQueuedForWithdrawal);
    }
```

Which means that owner has to set the validator caps for the operator again to recover that 1 ether which might not be possible since the owner decided to shutdown the entire validators for the specific operator. 

**Another scenario from same root cause:**
1- There are 64 ether in an operator 
2- Someone requests a withdrawal of 50 ether
3- All 64 ether is withdrawn from beacon chain 
4- 50 ether sent to the users withdrawal, 14 ether is idle in the EigenPod waiting for someone to call `scrapeExcessFullWithdrawalETHFromEigenPod`
5- An user quickly withdraws 13 ether
6- `withdrawableRestakedExecutionLayerGwei` is 1 ether and `INSUFFICIENT_EXCESS_FULL_WITHDRAWAL_ETH` also 1 ether. Which means the 1 ether can't be re-added to deposit pool until someone withdraws.

**Coded PoC:**
```solidity
// forge test --match-contract RioLRTOperatorDelegatorTest --match-test test_StakeETHCalledWith0Ether -vv
    function test_StuckEther() public {
        uint8 operatorId = addOperatorDelegator(reETH.operatorRegistry, address(reETH.rewardDistributor));
        address operatorDelegator = reETH.operatorRegistry.getOperatorDetails(operatorId).delegator;

        uint256 TVL = 64 ether;
        uint256 WITHDRAWAL_AMOUNT = 63 ether;
        RioLRTOperatorDelegator delegatorContract = RioLRTOperatorDelegator(payable(operatorDelegator));

        // Allocate ETH.
        reETH.coordinator.depositETH{value: TVL - address(reETH.depositPool).balance}();


        // Push funds into EigenLayer.
        vm.prank(EOA, EOA);
        reETH.coordinator.rebalance(ETH_ADDRESS);


        // Verify validator withdrawal credentials.
        uint40[] memory validatorIndices = verifyCredentialsForValidators(reETH.operatorRegistry, operatorId, 2);


        // Verify and process two full validator exits.
        verifyAndProcessWithdrawalsForValidatorIndexes(operatorDelegator, validatorIndices);

        // Withdraw some funds.
        reETH.coordinator.requestWithdrawal(ETH_ADDRESS, WITHDRAWAL_AMOUNT);
        uint256 withdrawalEpoch = reETH.withdrawalQueue.getCurrentEpoch(ETH_ADDRESS);

        // Skip ahead and rebalance to queue the withdrawal within EigenLayer.
        skip(reETH.coordinator.rebalanceDelay());

        vm.prank(EOA, EOA);
        reETH.coordinator.rebalance(ETH_ADDRESS);

        // Verify and process two full validator exits.
        verifyAndProcessWithdrawalsForValidatorIndexes(operatorDelegator, validatorIndices);

        // Settle with withdrawal epoch.
        IDelegationManager.Withdrawal[] memory withdrawals = new IDelegationManager.Withdrawal[](1);
        withdrawals[0] = IDelegationManager.Withdrawal({
            staker: operatorDelegator,
            delegatedTo: address(1),
            withdrawer: address(reETH.withdrawalQueue),
            nonce: 0,
            startBlock: 1,
            strategies: BEACON_CHAIN_STRATEGY.toArray(),
            shares: WITHDRAWAL_AMOUNT.toArray()
        });
        reETH.withdrawalQueue.settleEpochFromEigenLayer(ETH_ADDRESS, withdrawalEpoch, withdrawals, new uint256[](1));

        vm.expectRevert(bytes4(keccak256("INSUFFICIENT_EXCESS_FULL_WITHDRAWAL_ETH()")));
        delegatorContract.scrapeExcessFullWithdrawalETHFromEigenPod();
    }
```

## Impact
Owner needs to set the caps again to recover the 1 ether. However, the validators are removed for a reason and adding operators again would probably be not intended since it was a shutdown. Hence, I'll label this as medium.
## Code Snippet
https://github.com/Layr-Labs/eigenlayer-contracts/blob/6de01c6c16d6df44af15f0b06809dc160eac0ebf/src/contracts/pods/EigenPod.sol#L294-L345

https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTOperatorRegistry.sol#L236-L253

https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/utils/OperatorRegistryV1Admin.sol#L276-L319

https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTOperatorDelegator.sol#L225-L227

https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/utils/OperatorRegistryV1Admin.sol#L144-L165

https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTOperatorDelegator.sol#L253-L273

https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTCoordinator.sol#L99-L116

https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/utils/OperatorOperations.sol#L88-L107

https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTOperatorDelegator.sol#L160-L167
## Tool used

Manual Review

## Recommendation
Make an emergency function which owner can scrape the excess eth regardless of `MIN_EXCESS_FULL_WITHDRAWAL_ETH_FOR_SCRAPE`