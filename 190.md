Rural Tweed Lemur

medium

# Stakers can avoid validator penalties

## Summary
Stakers can frontrun validators penalties and slashing events with a withdrawal request in order to avoid the loss, this is possible if the deposit pool has enough liquidity available.

## Vulnerability Detail
Validators can lose part of their deposit via [penalties](https://eth2book.info/capella/part2/incentives/penalties/) or [slashing](https://eth2book.info/capella/part2/incentives/slashing/) events:
- In case of penalties Eigenlayer can be notified of the balance drop via the permissionless function 
[EigenPod::verifyBalanceUpdates()](https://github.com/Layr-Labs/eigenlayer-contracts/blob/v0.2.1-goerli-m2/src/contracts/pods/EigenPod.sol#L185). 
- In case of slashing the validator is forced to exit and Eigenlayer can be notified via the permissionless function [EigenPod::verifyAndProcessWithdrawals()](https://github.com/Layr-Labs/eigenlayer-contracts/blob/v0.2.1-goerli-m2/src/contracts/pods/EigenPod.sol#L232) because the slashing event is effectively a full withdrawal.

As soon as either [EigenPod::verifyBalanceUpdates()](https://github.com/Layr-Labs/eigenlayer-contracts/blob/v0.2.1-goerli-m2/src/contracts/pods/EigenPod.sol#L185) or [EigenPod::verifyAndProcessWithdrawals()](https://github.com/Layr-Labs/eigenlayer-contracts/blob/v0.2.1-goerli-m2/src/contracts/pods/EigenPod.sol#L232) is called the TVL of the Rio protocol drops instantly. This is because both of the functions update the variable [`podOwnerShares[podOwner]`](https://github.com/Layr-Labs/eigenlayer-contracts/blob/v0.2.1-goerli-m2/src/contracts/pods/EigenPodManager.sol#L120):
- [EigenPod::verifyBalanceUpdates()](https://github.com/Layr-Labs/eigenlayer-contracts/blob/v0.2.1-goerli-m2/src/contracts/pods/EigenPod.sol#L185) will update the variable [here](https://github.com/Layr-Labs/eigenlayer-contracts/blob/v0.2.1-goerli-m2/src/contracts/pods/EigenPod.sol#L220)
- [EigenPod::verifyAndProcessWithdrawals()](https://github.com/Layr-Labs/eigenlayer-contracts/blob/v0.2.1-goerli-m2/src/contracts/pods/EigenPod.sol#L232) will update the variable [here](https://github.com/Layr-Labs/eigenlayer-contracts/blob/v0.2.1-goerli-m2/src/contracts/pods/EigenPod.sol#L275)

This makes it possible for stakers to:
1. Request a withdrawal via [RioLRTCoordinator::rebalance()](https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/restaking/RioLRTCoordinator.sol#L99) for all the `LRTTokens` held.
2. Call either [EigenPod::verifyBalanceUpdates()](https://github.com/Layr-Labs/eigenlayer-contracts/blob/v0.2.1-goerli-m2/src/contracts/pods/EigenPod.sol#L185) or [EigenPod::verifyAndProcessWithdrawals()](https://github.com/Layr-Labs/eigenlayer-contracts/blob/v0.2.1-goerli-m2/src/contracts/pods/EigenPod.sol#L232).

At this point when [RioLRTCoordinator::rebalance()](https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/restaking/RioLRTCoordinator.sol#L121) will be called and a withdrawal will be queued that does not include penalties or slashing. 

It's possible to withdraw `LRTTokens` while avoiding penalties or slashing up to the amount of liquidity available in the deposit pool.

### POC
I wrote a POC whose main point is to show that requesting a withdrawal before an instant TVL drop will withdraw the full amount requested without taking the drop into account. The POC doesn't show that [EigenPod::verifyBalanceUpdates()](https://github.com/Layr-Labs/eigenlayer-contracts/blob/v0.2.1-goerli-m2/src/contracts/pods/EigenPod.sol#L185) or [EigenPod::verifyAndProcessWithdrawals()](https://github.com/Layr-Labs/eigenlayer-contracts/blob/v0.2.1-goerli-m2/src/contracts/pods/EigenPod.sol#L232) actually lowers the TVL because I wasn't able to implement it in the tests.

Add imports to `RioLRTCoordinator.t.sol`:
```solidity
import {IRioLRTOperatorRegistry} from 'contracts/interfaces/IRioLRTOperatorRegistry.sol';
import {RioLRTOperatorDelegator} from 'contracts/restaking/RioLRTOperatorDelegator.sol';
import {CredentialsProofs, BeaconWithdrawal} from 'test/utils/beacon-chain/MockBeaconChain.sol';
```

then copy-paste:
```solidity
IRioLRTOperatorRegistry.StrategyShareCap[] public emptyStrategyShareCaps;
function test_avoidInstantPriceDrop() public {
    //-> Add two operators with 1 validator each
    uint8[] memory operatorIds = addOperatorDelegators(
        reETH.operatorRegistry,
        address(reETH.rewardDistributor),
        2,
        emptyStrategyShareCaps,
        1
    );
    address operatorAddress0 = address(uint160(1));

    //-> Deposit ETH so there's 74ETH in the deposit pool
    uint256 depositAmount = 2*ETH_DEPOSIT_SIZE - address(reETH.depositPool).balance;
    uint256 amountToWithdraw = 10 ether;
    reETH.coordinator.depositETH{value: amountToWithdraw + depositAmount}();

    //-> Stake the 64ETH on the validators, 32ETH each and 10 ETH stay in the deposit pool
    vm.prank(EOA, EOA);
    reETH.coordinator.rebalance(ETH_ADDRESS);

    //-> Attacker notices a validator is going receive penalties and immediately requests a withdrawal of 10ETH
    reETH.coordinator.requestWithdrawal(ETH_ADDRESS, amountToWithdraw);

    //-> Validator get some penalties and Eigenlayer notified 
    //IMPORTANT: The following block of code it's a simulation of what would happen if a validator balances gets lowered because of penalties
    //and `verifyBalanceUpdates()` gets called on Eigenlayer. It uses another bug to achieve an instant loss of TVL.

    //      ~~~Start penalties simulation~~~
    {
        //-> Verify validators credentials of the two validators
        verifyCredentialsForValidators(reETH.operatorRegistry, 1, 1);
        verifyCredentialsForValidators(reETH.operatorRegistry, 2, 1);

        //-> Cache current TVL and ETH Balance
        uint256 TVLBefore = reETH.coordinator.getTVL();

        //->Operator calls `undelegate()` on Eigenlayer
        //IMPORTANT: This achieves the same a calling `verifyBalanceUpdates()` on Eigenlayer after a validator suffered penalties,
        //an instant drop in TVL.
        IRioLRTOperatorRegistry.OperatorPublicDetails memory details = reETH.operatorRegistry.getOperatorDetails(operatorIds[0]);
        vm.prank(operatorAddress0);
        delegationManager.undelegate(details.delegator);

        //-> TVL dropped
        uint256 TVLAfter = reETH.coordinator.getTVL();

        assertLt(TVLAfter, TVLBefore);
    }
    //      ~~~End penalties simulation~~~

    //-> Rebalance gets called
    skip(reETH.coordinator.rebalanceDelay());
    vm.prank(EOA, EOA);
    reETH.coordinator.rebalance(ETH_ADDRESS);

    //-> Attacker receives all of the ETH he withdrew, avoiding the effect of penalties
    uint256 balanceBefore = address(this).balance;
    reETH.withdrawalQueue.claimWithdrawalsForEpoch(IRioLRTWithdrawalQueue.ClaimRequest({asset: ETH_ADDRESS, epoch: 0}));
    uint256 balanceAfter = address(this).balance;
    assertEq(balanceAfter - balanceBefore, amountToWithdraw);
}
```

## Impact
Stakers can avoid validator penalties and slashing events if there's enough liquidity in the deposit pool.

## Code Snippet

## Tool used

Manual Review

## Recommendation
When [RioLRTCoordinator::rebalance()](https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/restaking/RioLRTCoordinator.sol#L121) is called and penalties or slashing events happened during the epoch being settled, distribute the correct amount of penalties to all the `LRTTokens` withdrawn in the current epoch, including the ones that requested the withdrawal before the drop.
