Rural Tweed Lemur

high

# The protocol can't receive rewards because of low gas limits on ETH transfers

## Summary
The hardcoded gas limit of the [Asset::transferETH()](https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/utils/Asset.sol#L41-L46) function, used to transfer ETH in the protocol, is too low and will result unwanted reverts.

## Vulnerability Detail
ETH transfers in the protocol are always done via [Asset::transferETH()](https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/utils/Asset.sol#L41-L46), which performs a low-level call with an hardcoded gas limit of `10_000`:
```solidity
(bool success,) = recipient.call{value: amount, gas: 10_000}('');
if (!success) {revert ETH_TRANSFER_FAILED();}
```

The hardcoded `10_000` gas limit is not high enough for the protocol to be able receive and distribute rewards. Rewards are currently only available for native ETH, an are received by Rio via:
- Partial withdrawals
- ETH in excess of `32ETH` on full withdrawals

The flow to receive rewards requires two steps:
1. An initial call to [EigenPod::verifyAndProcessWithdrawals()](https://github.com/Layr-Labs/eigenlayer-contracts/blob/v0.2.1-goerli-m2/src/contracts/pods/EigenPod.sol#L232), which queues a withdrawal to the Eigenpod owner: an `RioLRTOperatorDelegator` instance
2. A call to [DelayedWithdrawalRouter::claimDelayedWithdrawals()](https://github.com/Layr-Labs/eigenlayer-contracts/blob/v0.2.1-goerli-m2/src/contracts/pods/DelayedWithdrawalRouter.sol#L99).

The call to [DelayedWithdrawalRouter::claimDelayedWithdrawals()](https://github.com/Layr-Labs/eigenlayer-contracts/blob/v0.2.1-goerli-m2/src/contracts/pods/DelayedWithdrawalRouter.sol#L99) triggers the following flow:
1. ETH are transferred to the [RioLRTOperatorDelegator](https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/restaking/RioLRTOperatorDelegator.sol#L244-L246) instance, where the `receive()` function is triggered.
2. The `receive()` function of [RioLRTOperatorDelegator](https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/restaking/RioLRTOperatorDelegator.sol#L244-L246) transfers ETH via [Asset::transferETH()](https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/utils/Asset.sol#L41-L46) to the [RioLRTRewardDistributor](https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/restaking/RioLRTRewardDistributor.sol#L82-L94), where another `receive()` function is triggered.
3. The `receive()` function of [RioLRTRewardDistributor](https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/restaking/RioLRTRewardDistributor.sol#L82-L94) transfers ETH via [Asset::transferETH()](https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/utils/Asset.sol#L41-L46) to the `treasury`, the `operatorRewardPool` and the [`RioLRTDepositPool`](https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/restaking/RioLRTDepositPool.sol).

The gas is limited at `10_000` in step `2` and is not enough to perform step `3`, making it impossible for the protocol to receive rewards and leaving funds stuck.

### POC
Add the following imports to `RioLRTOperatorDelegator.t.sol`:
```solidity
import {IRioLRTOperatorRegistry} from 'contracts/interfaces/IRioLRTOperatorRegistry.sol';
import {RioLRTOperatorDelegator} from 'contracts/restaking/RioLRTOperatorDelegator.sol';
import {CredentialsProofs, BeaconWithdrawal} from 'test/utils/beacon-chain/MockBeaconChain.sol';
```

then copy-paste:
```solidity
function test_outOfGasOnRewards() public {
    address alice = makeAddr("alice");
    uint256 initialBalance = 40e18;
    deal(alice, initialBalance);
    vm.prank(alice);
    reETH.token.approve(address(reETH.coordinator), type(uint256).max);

    //->Operator delegator and validators are added to the protocol
    uint8 operatorId = addOperatorDelegator(reETH.operatorRegistry, address(reETH.rewardDistributor));
    RioLRTOperatorDelegator operatorDelegator =
        RioLRTOperatorDelegator(payable(reETH.operatorRegistry.getOperatorDetails(operatorId).delegator));

    //-> Alice deposits ETH in the protocol
    vm.prank(alice);
    reETH.coordinator.depositETH{value: initialBalance}();
    
    //-> Rebalance is called and the ETH deposited in a validator
    vm.prank(EOA, EOA);
    reETH.coordinator.rebalance(ETH_ADDRESS);

    //-> Create a new validator with a 40ETH balance and verify his credentials.
    //-> This is to "simulate" rewards accumulation
    uint40[] memory validatorIndices = new uint40[](1);
    IRioLRTOperatorRegistry.OperatorPublicDetails memory details = reETH.operatorRegistry.getOperatorDetails(operatorId);
    bytes32 withdrawalCredentials = operatorDelegator.withdrawalCredentials();
    beaconChain.setNextTimestamp(block.timestamp);
    CredentialsProofs memory proofs;
    (validatorIndices[0], proofs) = beaconChain.newValidator({
        balanceWei: 40 ether,
        withdrawalCreds: abi.encodePacked(withdrawalCredentials)
    });
    
    //-> Verify withdrawal crendetials
    vm.prank(details.manager);
    reETH.operatorRegistry.verifyWithdrawalCredentials(
        operatorId,
        proofs.oracleTimestamp,
        proofs.stateRootProof,
        proofs.validatorIndices,
        proofs.validatorFieldsProofs,
        proofs.validatorFields
    );

    //-> Process a full withdrawal, 8ETH (40ETH - 32ETH) will be queued withdrawal as "rewards"
    verifyAndProcessWithdrawalsForValidatorIndexes(address(operatorDelegator), validatorIndices);

    //-> Call `claimDelayedWithdrawals` to claim the withdrawal
    delayedWithdrawalRouter.claimDelayedWithdrawals(address(operatorDelegator), 1); //❌ Reverts for out-of-gas
}
```
## Impact
The protocol is unable to receive rewards and the funds will be stucked.

## Code Snippet

## Tool used

Manual Review

## Recommendation
Remove the hardcoded `10_000` gas limit in [Asset::transferETH()](https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/utils/Asset.sol#L41-L46), at least on ETH transfers where the destination is a protocol controlled contract.
