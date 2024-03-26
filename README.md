# Issue H-1: Creating new withdrawal requests in conjunction with `settleEpochFromEigenLayer` will render system unusable 

Source: https://github.com/sherlock-audit/2024-02-rio-network-core-protocol-judging/issues/4 

## Found by 
0xkaden, AuditorPraise, Aymen0909, Bauer, ComposableSecurity, Drynooo, HSP, KupiaSec, Stiglitz, Thanos, Tricko, almurhasan, aslanbek, bhilare\_, cu5t0mPe0, deth, eeshenggoh, fnanni, g, giraffe, hash, iamandreiski, jovi, kennedy1030, klaus, lemonmon, lil.eth, monrel, mstpr-brainbot, mussucal, peanuts, popular, sakshamguruji, shaka, thec00n, zraxx, zzykxx
## Summary
This issue pertains to the flow where a user requests to withdraw more funds than are currently present in the `depositPool` and the system must withdraw from Eigenlayer. 

Users are able to create new withdrawal requests for the current epoch while the Eigenlayer withdrawal request is pending, as well as after the epoch has been marked `settled` in `settleEpochFromEigenLayer()`. This is due to the fact that `settleEpochFromEigenLayer()` does not increment the current epoch, as well as that there is no way to fulfill withdrawal requests submitted after the 7 day waiting period has been initiated. Submitting a withdrawal request will result in an inability to progress epochs and a locking of the system. 

## Vulnerability Detail
Consider the system in the following state:
- We are in epoch 0
- A user submitted a withdrawal request for an amount greater than what is currently in `depositPool`
- `rebalance() --> withdrawalQueue_.queueCurrentEpochSettlement()` has been called
- The system made a request to Eigenlayer for the necessary amount and the withdrawal request is ready to be claimed
- The next step is to call `RioLRTWithdrawalQueue:settleEpochFromEigenLayer()` [link](https://github.com/sherlock-audit/2024-02-rio-vesting-core-protocol/blob/main/rio-sherlock-audit/contracts/restaking/RioLRTWithdrawalQueue.sol#L216)

The function `settleEpochFromEigenLayer()` performs several important tasks - completing pending withdrawals from Eigenlayer, accounting for the amounts received, burning the appropriate amount of LRTs, and marking the epoch as settled. It does NOT increment the epoch counter for the asset - the only way to do that is in `settleCurrentEpoch()`, which is only called in `rebalance()` when there is enough present in the `depositPool` to cover withdrawals. 

After calling `settleEpochFromEigenLayer()`, the system is in a state where the current epoch has been marked as settled. However, while waiting for the 7 day Eigenlayer delay it is possible that more users sent withdrawal requests. These withdrawal requests would be queued for epoch 0 (and increment `sharesOwed` for epoch 0) , but were not considered when performing the withdrawal from Eigenlayer. There is no way to process these requests, as the epoch has already been settled + we can only call `queueCurrentEpochSettlement` once per epoch due to the `if (epochWithdrawals.aggregateRoot != bytes32(0)) revert WITHDRAWALS_ALREADY_QUEUED_FOR_EPOCH();` check

Notably, users that requested withdrawals have already sent the LRT amount to be burned and are unable to reclaim their funds. 

Also note that there is no access control on `settleEpochFromEigenLayer()`, so as long as the provided withdrawal parameters are correct anybody can call the function. 

## Impact
Critical - system no longer operates, loss of users funds

## Code Snippet
The following test can be dropped into `RioLRTWithdrawalQueue.t.sol`
```solidity
 function test_lockAsset() public {
        uint8 operatorId = addOperatorDelegator(reETH.operatorRegistry, address(reETH.rewardDistributor));
        address operatorDelegator = reETH.operatorRegistry.getOperatorDetails(operatorId).delegator;

        // Deposit ETH, rebalance, and verify the validator withdrawal credentials.
        uint256 depositAmount = (ETH_DEPOSIT_SIZE - address(reETH.depositPool).balance);
        uint256 withdrawalAmount = 10 ether;
        assertGt(depositAmount, withdrawalAmount * 2); // We will be withdrawing twice
        reETH.coordinator.depositETH{value: depositAmount}();
        vm.prank(EOA, EOA);
        reETH.coordinator.rebalance(ETH_ADDRESS);
        uint40[] memory validatorIndices = verifyCredentialsForValidators(reETH.operatorRegistry, 1, 1);

        // Request a withdrawal and rebalance to kick off the Eigenlayer withdrawal process
        reETH.coordinator.requestWithdrawal(ETH_ADDRESS, withdrawalAmount);
        skip(reETH.coordinator.rebalanceDelay());
        vm.prank(EOA, EOA);
        reETH.coordinator.rebalance(ETH_ADDRESS);

        // Ensure no reETH has been burned yet and process withdrawals.
        assertEq(reETH.token.totalSupply(), ETH_DEPOSIT_SIZE);
        verifyAndProcessWithdrawalsForValidatorIndexes(operatorDelegator, validatorIndices);

        // Settle the withdrawal epoch. This marks the epoch as settled and
        // makes the requested withdrawal amount available to be claimed.
        uint256 withdrawalEpoch = reETH.withdrawalQueue.getCurrentEpoch(ETH_ADDRESS);
        IDelegationManager.Withdrawal[] memory withdrawals = new IDelegationManager.Withdrawal[](1);
        withdrawals[0] = IDelegationManager.Withdrawal({
            staker: operatorDelegator,
            delegatedTo: address(1),
            withdrawer: address(reETH.withdrawalQueue),
            nonce: 0,
            startBlock: 1,
            strategies: BEACON_CHAIN_STRATEGY.toArray(),
            shares: withdrawalAmount.toArray()
        });
        reETH.withdrawalQueue.settleEpochFromEigenLayer(ETH_ADDRESS, withdrawalEpoch, withdrawals, new uint256[](1));

        IRioLRTWithdrawalQueue.EpochWithdrawalSummary memory epochSummary =
            reETH.withdrawalQueue.getEpochWithdrawalSummary(ETH_ADDRESS, withdrawalEpoch);
        // Epoch is settled
        assertTrue(epochSummary.settled);

        // However, the epoch has not been incremented - we're still in epoch 0 even after settlement
        assertEq(reETH.withdrawalQueue.getCurrentEpoch(ETH_ADDRESS), 0);

        // We can still create new withdrawal requests for this epoch and increase sharesOwed
        uint256 sharesOwedBefore = epochSummary.sharesOwed;
        reETH.coordinator.requestWithdrawal(ETH_ADDRESS, withdrawalAmount);
        epochSummary = reETH.withdrawalQueue.getEpochWithdrawalSummary(ETH_ADDRESS, withdrawalEpoch);
        // Shares owed has increased
        assertGt(epochSummary.sharesOwed, sharesOwedBefore);

        // We've received one withdrawalAmount worth of assets from Eigenlayer
        assertEq(epochSummary.assetsReceived, withdrawalAmount);
        assertEq(epochSummary.shareValueOfAssetsReceived, withdrawalAmount);

        // Claim what was received from Eigenlayer (== one withdrawalAmount)
        uint256 balanceBefore = address(this).balance;
        uint256 amountOut = reETH.withdrawalQueue.claimWithdrawalsForEpoch(
            IRioLRTWithdrawalQueue.ClaimRequest({asset: ETH_ADDRESS, epoch: withdrawalEpoch})
        );
        IRioLRTWithdrawalQueue.UserWithdrawalSummary memory userSummary =
            reETH.withdrawalQueue.getUserWithdrawalSummary(ETH_ADDRESS, withdrawalEpoch, address(this));

        // The user has been marked as Claimed for this epoch, even though only one withdrawalAmount worth was claimed
        assertTrue(userSummary.claimed);
        assertEq(amountOut, withdrawalAmount);
        assertEq(address(this).balance - balanceBefore, withdrawalAmount);
        // sharesOwed for this epoch is 2 withdrawals worth (we're sitll missing one)
        assertEq(epochSummary.sharesOwed, withdrawalAmount * 2);

        // We can't rebalance because withdrawals have already been queued for this epoch
        // If we can't rebalance, we can't ever get to settleCurrentEpoch() to progress to the next epoch
        skip(reETH.coordinator.rebalanceDelay());
        vm.prank(EOA, EOA);
        vm.expectRevert(0x9a641da5); // WITHDRAWALS_ALREADY_QUEUED_FOR_EPOCH
        reETH.coordinator.rebalance(ETH_ADDRESS);

        // Current epoch is still 0
        assertEq(reETH.withdrawalQueue.getCurrentEpoch(ETH_ADDRESS), 0);

        // Reverts in pre-checks because the epoch has been marked as settled
        vm.expectRevert(0xad29946a); // EPOCH_ALREADY_SETTLED
        reETH.withdrawalQueue.settleEpochFromEigenLayer(ETH_ADDRESS, withdrawalEpoch, withdrawals, new uint256[](1));
    }
```
## Tool used

Manual Review

## Recommendation
Consider incrementing the current epoch as soon as the withdrawal process has been initiated, such that user withdrawal requests sent after an epoch has been queued for settlement will be considered a part of the next epoch



## Discussion

**solimander**

Valid bug - `currentEpochsByAsset[asset] += 1;` should be called in `queueCurrentEpochSettlement`.

**sherlock-admin4**

The protocol team fixed this issue in PR/commit https://github.com/rio-org/rio-sherlock-audit/pull/1.

# Issue H-2: Setting the strategy cap to "0" does not update the total shares held or the withdrawal queue 

Source: https://github.com/sherlock-audit/2024-02-rio-network-core-protocol-judging/issues/10 

## Found by 
Aymen0909, KupiaSec, g, hash, kennedy1030, mstpr-brainbot
## Summary
Removing or setting the strategy cap to 0 will not decrease the shares held in the system. Additionally, it will not update the withdrawal queue, which means users can request withdrawals, and the withdrawals will exceed the allocated amount when rebalance occurs.
## Vulnerability Detail
Let's go over the issue with an example:

Assume there is 1 strategy and 2 operators active in an LSR with total strategy shares holding is 1000 * 1e18 where both operators shares 500-500 the assets. 

When the owner decides to inactivate or just simply sets one of the operators cap to "0" the operator will withdraw all its assets as follows:
```solidity
function setOperatorStrategyCap(
        RioLRTOperatorRegistryStorageV1.StorageV1 storage s,
        uint8 operatorId,
        IRioLRTOperatorRegistry.StrategyShareCap memory newShareCap
    ) internal {
        . 
        // @review this "if" will be executed
        -> if (currentShareDetails.cap > 0 && newShareCap.cap == 0) {
            // If the operator has allocations, queue them for exit.
            if (currentShareDetails.allocation > 0) {
                -> operatorDetails.queueOperatorStrategyExit(operatorId, newShareCap.strategy);
            }
            // Remove the operator from the utilization heap.
            utilizationHeap.removeByID(operatorId);
        } else if (currentShareDetails.cap == 0 && newShareCap.cap > 0) {
            // If the current cap is 0 and the new cap is greater than 0, insert the operator into the heap.
            utilizationHeap.insert(OperatorUtilizationHeap.Operator(operatorId, 0));
        } else {
            // Otherwise, update the operator's utilization in the heap.
            utilizationHeap.updateUtilizationByID(operatorId, currentShareDetails.allocation.divWad(newShareCap.cap));
        }
        .
    }
```
```solidity
function queueOperatorStrategyExit(IRioLRTOperatorRegistry.OperatorDetails storage operator, uint8 operatorId, address strategy) internal {
        .
        // @review asks delegator to exit
        -> bytes32 withdrawalRoot = delegator.queueWithdrawalForOperatorExit(strategy, sharesToExit);
        emit IRioLRTOperatorRegistry.OperatorStrategyExitQueued(operatorId, strategy, sharesToExit, withdrawalRoot);
    }
```

Then the operator delegator contract calls the EigenLayer to withdraw all its balance as follows:
```solidity
function _queueWithdrawalForOperatorExitOrScrape(address strategy, uint256 shares) internal returns (bytes32 root) {
       . // @review jumps to internal function
        -> root = _queueWithdrawal(strategy, shares, address(depositPool()));
    }

function _queueWithdrawal(address strategy, uint256 shares, address withdrawer) internal returns (bytes32 root) {
        IDelegationManager.QueuedWithdrawalParams[] memory withdrawalParams = new IDelegationManager.QueuedWithdrawalParams[](1);
        withdrawalParams[0] = IDelegationManager.QueuedWithdrawalParams({
            strategies: strategy.toArray(),
            shares: shares.toArray(),
            withdrawer: withdrawer
        });
        // @review calls Eigen layer to queue all the balance and returns the root
        -> root = delegationManager.queueWithdrawals(withdrawalParams)[0];
    }
```

Which we can observe from the above snippet the EigenLayer is called for the withdrawal and then the entire function execution ends. The problem is `assetRegistry` still thinks there are 1000 * 1e18 EigenLayer shares in the operators. Also, the `withdrawalQueue` is not aware of this withdrawal request which means that users can call `requestWithdrawal` to withdraw up to 1000 * 1e18 EigenLayer shares worth LRT but in reality the 500 * 1e18 portion of it already queued in withdrawal by the owner of operator registry.

**Coded PoC:**
```solidity
function test_SettingStrategyCapZero_WithdrawalsAreDoubleCountable() public {
        IRioLRTOperatorRegistry.StrategyShareCap[] memory zeroStrategyShareCaps =
            new IRioLRTOperatorRegistry.StrategyShareCap[](2);
        zeroStrategyShareCaps[0] = IRioLRTOperatorRegistry.StrategyShareCap({strategy: RETH_STRATEGY, cap: 0});
        zeroStrategyShareCaps[1] = IRioLRTOperatorRegistry.StrategyShareCap({strategy: CBETH_STRATEGY, cap: 0});

        uint8 operatorId = addOperatorDelegator(reLST.operatorRegistry, address(reLST.rewardDistributor));

        uint256 AMOUNT = 111e18;

        // Allocate to cbETH strategy.
        cbETH.approve(address(reLST.coordinator), type(uint256).max);
        uint256 lrtAmount = reLST.coordinator.deposit(CBETH_ADDRESS, AMOUNT);

        // Push funds into EigenLayer.
        vm.prank(EOA, EOA);
        reLST.coordinator.rebalance(CBETH_ADDRESS);

        vm.recordLogs();
        reLST.operatorRegistry.setOperatorStrategyShareCaps(operatorId, zeroStrategyShareCaps);

        Vm.Log[] memory entries = vm.getRecordedLogs();
        assertGt(entries.length, 0);

        for (uint256 i = 0; i < entries.length; i++) {
            if (entries[i].topics[0] == keccak256('OperatorStrategyExitQueued(uint8,address,uint256,bytes32)')) {
                uint8 emittedOperatorId = abi.decode(abi.encodePacked(entries[i].topics[1]), (uint8));
                (address strategy, uint256 sharesToExit, bytes32 withdrawalRoot) =
                    abi.decode(entries[i].data, (address, uint256, bytes32));

                assertEq(emittedOperatorId, operatorId);
                assertEq(strategy, CBETH_STRATEGY);
                assertEq(sharesToExit, AMOUNT);
                assertNotEq(withdrawalRoot, bytes32(0));

                break;
            }
            if (i == entries.length - 1) fail('Event not found');
        }

        // @review add these
        // @review all the eigen layer shares are already queued as we checked above, now user requestWithdrawal
        // of the same amount of EigenLayer share worth of LRT which there will be double counting when epoch is settled.
        uint256 queuedShares = reLST.coordinator.requestWithdrawal(address(cbETH), lrtAmount);
        console.log("Queued shares", queuedShares);
    }
```
## Impact
High, because the users withdrawals will never go through in rebalancing because of double counting of the same share withdrawals.
## Code Snippet
https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/utils/OperatorRegistryV1Admin.sol#L231-L270

https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/utils/OperatorRegistryV1Admin.sol#L144-L165

https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTOperatorDelegator.sol#L225-L227

https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTOperatorDelegator.sol#L253-L258

https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTOperatorDelegator.sol#L265-L273
## Tool used

Manual Review

## Recommendation
Update the withdrawal queue when the operator registry admin changes the EigenLayer shares amount by either removing an operator or setting its strategy cap to "0".

# Issue H-3: Malicious operators can `undelegate` theirselves to manipulate the LRT exchange rate 

Source: https://github.com/sherlock-audit/2024-02-rio-network-core-protocol-judging/issues/53 

## Found by 
g, giraffe, hash, mstpr-brainbot, zzykxx
## Summary
If a malicious operator undelegates itself in EigenLayer delegation manager contract, the exchange rate of LRT can significantly decrease, and ETH/LST can become stuck, unable to be claimed by the Rio Delegator Approver contract.
## Vulnerability Detail
Operators' delegator contracts delegate their balance to the operators. Operators can "undelegate" themselves from any delegation forwarded to them by triggering this function:
[DelegationManager.sol#L211-L258](https://github.com/Layr-Labs/eigenlayer-contracts/blob/6de01c6c16d6df44af15f0b06809dc160eac0ebf/src/contracts/core/DelegationManager.sol#L211-L258).

If the operator `undelegate` the delegator approver, then according to the strategy, there can be two things that happen:

1- Strategy shares:
When the operator undelegates, the strategy shares delegated to the operator will be queued for withdrawal to the stakee address. In this case, the `staker` is the RIO operator delegator contract, which has no implementation to withdraw the queued withdrawal request since the withdrawer must be the "msg.sender." Therefore, the operator delegator must implement that functionality in such cases. The only downside to this is that the accounting of strategy shares to operators is tracked internally and not relied upon the StrategyManager's actual shares in the EigenLayer contract.

2- EigenPod shares:
When EigenPod shares are `undelegate`, the EigenPod shares are removed. Unlike the strategy shares, the EigenPod shares are used to account for how much ETH is held by each operator. If an operator `undelegate`, then the entire EigenPod balance will be "0," and the RIO contracts are not prepared for this. This will erase a large amount of ETH TVL held by the Beacon Chain strategy, hence the LRT token exchange rate will change dramatically. Also, as with the above strategy shares issue, the `staker` is the operator delegator; hence, the operator delegator must implement the withdrawal functionality to be able to withdraw the ETH balance from the EigenPod.
## Impact
High because of the "EigenPod shares" issue can unexpectedly decrease the TVL, leading to a decrease in the LRT exchange rate without warning which would affect the deposits/withdrawals of the LRT in different assets aswell. 

**Coded PoC:**
```solidity
// forge test --match-contract RioLRTOperatorRegistryTest --match-test test_UndelegateRemovesEigenPodShares -vv
    function test_UndelegateRemovesEigenPodShares() public {
        uint8 operatorId =
            addOperatorDelegator(reETH.operatorRegistry, address(reETH.rewardDistributor), emptyStrategyShareCaps, 10);
        
        // @review make a deposit
        reETH.coordinator.depositETH{value: 32 * 5 ether}();

        // Push funds into EigenLayer.
        vm.prank(EOA, EOA);
        reETH.coordinator.rebalance(ETH_ADDRESS);

        // Verify validator withdrawal credentials.
        uint40[] memory validatorIndices = verifyCredentialsForValidators(reETH.operatorRegistry, operatorId, 5);

        // @review get the addresses 
        address operatorDelegator = reETH.operatorRegistry.getOperatorDetails(operatorId).delegator;
        RioLRTOperatorDelegator delegatorContract = RioLRTOperatorDelegator(payable(operatorDelegator));

        // @review all ether is in eigen pod shares 
        assertEq(uint256(delegatorContract.getEigenPodShares()), 32 * 5 * 1e18);
        // @review the TVL is the 32*5 ether and the initial deposit
        assertEq(reETH.assetRegistry.getTVLForAsset(ETH_ADDRESS), 160010000000000000000);

        // @review undelegate from the operator 
        vm.prank(address(uint160(0 + 1)));
        delegationManager.undelegate(operatorDelegator);

        // @review eigenpod shares are removed fully
        assertEq(uint256(delegatorContract.getEigenPodShares()), 0);
        // @review the TVL is only the initial deposit
        assertEq(reETH.assetRegistry.getTVLForAsset(ETH_ADDRESS), 10000000000000000);
    }
```
## Code Snippet
https://github.com/Layr-Labs/eigenlayer-contracts/blob/6de01c6c16d6df44af15f0b06809dc160eac0ebf/src/contracts/core/DelegationManager.sol#L211-L258

## Tool used

Manual Review

## Recommendation



## Discussion

**solimander**

Valid, but feels like it should be medium given precondition that you must be voted into the active operator set.

**nevillehuang**

Since operators are not trusted in the context of rio-protocol, I believe high severity to be appropriate since this allows direct manipulation of exchange rates and can cause stuck funds within rio contracts

# Issue H-4: Deposits may be front-run by malicious operator to steal ETH 

Source: https://github.com/sherlock-audit/2024-02-rio-network-core-protocol-judging/issues/55 

## Found by 
giraffe, hash, zzykxx
## Summary
Delegated staking protocols may be exposed to a [known vulnerability](https://ethresear.ch/t/deposit-contract-exploit/6528), where a malicious operator front-runs a staker’s deposit call to the Beacon chain deposit contract and provides a different withdrawal credentials. This issue impacts Rio Network as well. 

## Vulnerability Detail
In Rio Network, approved operators are added to the operator registry. Thereafter, the operator adds validator details (public keys, signatures) to the same registry and awaits a confirmation period to pass (keys which are invalid may be removed by a security daemon) before the validators are active and ready to receive ETH. 

When ETH is deposited and ready to be staked, RioLRTOperatorDelegator:stakeETH() is called which in turns calls `eigenPodManager.stake{value: ETH_DEPOSIT_SIZE}(publicKey, signature, depositDataRoot);` The withdrawal credentials point to the OperatorDelegator's Eigenpod.

A malicious operator may however front-run this transaction, by depositing 1 ETH into the Beacon chain deposit contract with the same validator keys but with a different, operator-controlled withdrawal credentials. Rio's OperatorDelegator's transaction would be successfully processed but the withdrawal credentials provided by the operator will **not be overwritten**. 

The end state is a validator managing 1 ETH of node operator’s funds and 32 ETH of Rio users’ funds, fully controlled and withdrawable by the node operator.
## Impact
While operators are trusted by the DAO, incoming ETH deposits could be as large as `ETH_DEPOSIT_SOFT_CAP` which is 3200 ETH, a sizeable incentive for an operator to turn malicious and easily carry out the attack (cost of attack = 1 ETH per validator). In fact, incoming deposits could exceed the soft cap (i.e. multiples of 3200 ETH), as several `rebalance` could be called without delay to deposit all the ETH over a few blocks. 

All deposited funds would be lost in such an attack.

This vulnerability also affected several LST/LRT protocols, see [Lido](https://research.lido.fi/t/mitigations-for-deposit-front-running-vulnerability/1239) and [EtherFi](https://246895607-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FG3Lk76lfvw9ecPIg0mK8%2Fuploads%2FFgdNivH2FNNe7JwkZXtd%2FNM0093-FINAL-ETHER-FI.pdf?alt=media&token=5aa1a2dc-33c7-430d-a2cb-59f56d2cfd2b) reports.

## Code Snippet
https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/restaking/RioLRTOperatorDelegator.sol#L204

## Tool used
Manual Review

## Recommendation
The Lido discussion extensively discusses possible solutions. My recommendations would be:
1) In order for validator key entries submitted by a node operator to be approved by the DAO, require the operator to pre-deposit 1 ETH with the correct protocol-controlled WC for each public key used in these deposit data entries. And upon approval of the validator keys, refund the operator the pre-deposited 1 ETH.
or,
2) Adopt what Lido did which was to establish a committee of guardians who will be tasked to watch for the deposit contract and publish a signed message off-chain to allow deposit.

Rio should also consider reducing the incentives for an operator to act maliciously by 1) reducing the maximum amount of ETH which can be deposited in a single tx, and 2) implement a short delay between rebalances, even if the soft cap was hit (to prevent chaining rebalances to deposit a large amount of ETH).



## Discussion

**nevillehuang**

Since operators are not trusted in the context of rio-protocol, I believe high severity to be appropriate since this allows direct stealing of material amount of funds

# Issue H-5: swapValidatorDetails incorrectly writes keys to memory, resulting in permanently locked beacon chain deposits 

Source: https://github.com/sherlock-audit/2024-02-rio-network-core-protocol-judging/issues/84 

## Found by 
0xkaden, Stiglitz, hash
## Summary

When loading BLS public keys from storage to memory, the keys are partly overwritten with zero bytes. This ultimately causes allocations of these malformed public keys to permanently lock deposited ETH in the beacon chain deposit contract.

## Vulnerability Detail

ValidatorDetails.swapValidatorDetails is used by RioLRTOperatorRegistry.reportOutOfOrderValidatorExits to swap the details in storage of validators which have been exited out of order:

```solidity
// Swap the position of the validators starting from the `fromIndex` with the validators that were next in line to be exited.
VALIDATOR_DETAILS_POSITION.swapValidatorDetails(operatorId, fromIndex, validators.exited, validatorCount);
```

In swapValidatorDetails, for each swap to occur, we load two keys into memory from storage:

```solidity
keyOffset1 = position.computeStorageKeyOffset(operatorId, startIndex1);
keyOffset2 = position.computeStorageKeyOffset(operatorId, startIndex2);
assembly {
    // Load key1 into memory
    let _part1 := sload(keyOffset1) // Load bytes 0..31
    let _part2 := sload(add(keyOffset1, 1)) // Load bytes 32..47
    mstore(add(key1, 0x20), _part1) // Store bytes 0..31
    mstore(add(key1, 0x30), shr(128, _part2)) // Store bytes 16..47

    isEmpty := iszero(or(_part1, _part2)) // Store if key1 is empty

    // Load key2 into memory
    _part1 := sload(keyOffset2) // Load bytes 0..31
    _part2 := sload(add(keyOffset2, 1)) // Load bytes 32..47
    mstore(add(key2, 0x20), _part1) // Store bytes 0..31
    mstore(add(key2, 0x30), shr(128, _part2)) // Store bytes 16..47

    isEmpty := or(isEmpty, iszero(or(_part1, _part2))) // Store if key1 or key2 is empty
}
```

The problem here is that when we store the keys in memory, they don't end up as intended. Let's look at how it works to see where it goes wrong.

The keys used here are BLS public keys, with a length of 48 bytes, e.g.: `0x95cfcb859956953f9834f8b14cdaa939e472a2b5d0471addbe490b97ed99c6eb8af94bc3ba4d4bfa93d087d522e4b78d`. As such, previously to entering this for loop, we initialize key1 and key2 in memory as 48 byte arrays:

```solidity
bytes memory key1 = new bytes(48);
bytes memory key2 = new bytes(48);
```

Since they're longer than 32 bytes, they have to be stored in two separate storage slots, thus we do two sloads per key to retrieve `_part1` and `_part2`, containing the first 32 bytes and the last 16 bytes respectively.

The following lines are used with the intention of storing the key in two separate memory slots, similarly to how they're stored in storage:

```solidity
mstore(add(key1, 0x20), _part1) // Store bytes 0..31
mstore(add(key1, 0x30), shr(128, _part2)) // Store bytes 16..47
```

The problem however is that the second mstore shifts `_part2` 128 bits to the right, causing the leftmost 128 bits to zeroed. Since this mstore is applied only 16 (0x10) bytes after the first mstore, we overwrite bytes 16..31 with zero bytes. We can test this in chisel to prove it:

Using this example key: `0x95cfcb859956953f9834f8b14cdaa939e472a2b5d0471addbe490b97ed99c6eb8af94bc3ba4d4bfa93d087d522e4b78d`

We assign the first 32 bytes to `_part1`: 
```solidity
bytes32 _part1 = 0x95cfcb859956953f9834f8b14cdaa939e472a2b5d0471addbe490b97ed99c6eb
```

We assign the last 16 bytes to `_part2`: 
```solidity
bytes32 _part2 = bytes32(bytes16(0x8af94bc3ba4d4bfa93d087d522e4b78d))
```

We assign 48 bytes in memory for `key1`:
```solidity
bytes memory key1 = new bytes(48);
```

And we run the following snippet from swapValidatorDetails in chisel: 
```solidity
assembly {
  mstore(add(key1, 0x20), _part1) // Store bytes 0..31
  mstore(add(key1, 0x30), shr(128, _part2)) // Store bytes 16..47
}
```

Now we can check the resulting memory using `!memdump`, which outputs the following:

```solidity
➜ !memdump
[0x00:0x20]: 0x0000000000000000000000000000000000000000000000000000000000000000
[0x20:0x40]: 0x0000000000000000000000000000000000000000000000000000000000000000
[0x40:0x60]: 0x00000000000000000000000000000000000000000000000000000000000000e0
[0x60:0x80]: 0x0000000000000000000000000000000000000000000000000000000000000000
[0x80:0xa0]: 0x0000000000000000000000000000000000000000000000000000000000000030
[0xa0:0xc0]: 0x95cfcb859956953f9834f8b14cdaa93900000000000000000000000000000000
[0xc0:0xe0]: 0x8af94bc3ba4d4bfa93d087d522e4b78d00000000000000000000000000000000
```

We can see from the memory that at the free memory pointer, the length of key1 is defined 48 bytes (0x30), and following it is the resulting key with 16 bytes zeroed in the middle of the key.

## Impact

Whenever we swapValidatorDetails using reportOutOfOrderValidatorExits, both sets of validators will have broken public keys and when allocated to will cause ETH to be permanently locked in the beacon deposit contract. 

We can see how this manifests in allocateETHDeposits where we retrieve the public keys for allocations:

```solidity
// Load the allocated validator details from storage and update the deposited validator count.
(pubKeyBatch, signatureBatch) = ValidatorDetails.allocateMemory(newDepositAllocation);
VALIDATOR_DETAILS_POSITION.loadValidatorDetails(
    operatorId, validators.deposited, newDepositAllocation, pubKeyBatch, signatureBatch, 0
);
...
allocations[allocationIndex] = OperatorETHAllocation(operator.delegator, newDepositAllocation, pubKeyBatch, signatureBatch);
```

We then use the public keys to stakeETH:

```solidity
(uint256 depositsAllocated, IRioLRTOperatorRegistry.OperatorETHAllocation[] memory allocations) = operatorRegistry.allocateETHDeposits(
    depositCount
);
depositAmount = depositsAllocated * ETH_DEPOSIT_SIZE;

for (uint256 i = 0; i < allocations.length; ++i) {
    uint256 deposits = allocations[i].deposits;

    IRioLRTOperatorDelegator(allocations[i].delegator).stakeETH{value: deposits * ETH_DEPOSIT_SIZE}(
        deposits, allocations[i].pubKeyBatch, allocations[i].signatureBatch
    );
}
```

Ultimately for each allocation, the public key is passed to the beacon DepositContract.deposit where it deposits to a public key for which we don't have the associated private key and thus can never withdraw.

## Code Snippet

- https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/utils/ValidatorDetails.sol#L151
- https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/utils/ValidatorDetails.sol#L159

## Tool used

Manual Review

## Recommendation

We can solve this by simply mstoring `_part2` prior to mstoring `_part1`, allowing the mstore of `_part1` to overwrite the zero bytes from `_part2`:

```solidity
mstore(add(key1, 0x30), shr(128, _part2)) // Store bytes 16..47
mstore(add(key1, 0x20), _part1) // Store bytes 0..31
```

Note that the above change must be made for both keys.



## Discussion

**sherlock-admin4**

The protocol team fixed this issue in PR/commit https://github.com/rio-org/rio-sherlock-audit/pull/2.

# Issue H-6: `reportOutOfOrderValidatorExits` does not updates the heap order 

Source: https://github.com/sherlock-audit/2024-02-rio-network-core-protocol-judging/issues/131 

## Found by 
ComposableSecurity, g, mstpr-brainbot
## Summary
When an operator's validator exits without a withdrawal request, the owner can invoke the `reportOutOfOrderValidatorExits` function to increase the `exited` portion of the operator validators. However, this action does not update the heap. Consequently, during subsequent allocation or deallocation processes, the heap may incorrectly mark validators as exited.
## Vulnerability Detail
First, let's see how the utilization is determined for native ETH deposits for operators which is calculated as:
`operatorShares.allocation.divWad(operatorShares.cap)` where as the allocation is the total `deposited` validators and the `cap` is predetermined value by the owner of the registry.

When the heap is retrieved from the storage, here how it is fetched:
```solidity
function getOperatorUtilizationHeapForETH(RioLRTOperatorRegistryStorageV1.StorageV1 storage s)
        internal
        view
        returns (OperatorUtilizationHeap.Data memory heap)
    {
        uint8 numActiveOperators = s.activeOperatorCount;
        if (numActiveOperators == 0) return OperatorUtilizationHeap.Data(new OperatorUtilizationHeap.Operator[](0), 0);

        heap = OperatorUtilizationHeap.initialize(MAX_ACTIVE_OPERATOR_COUNT);

        uint256 activeDeposits;
        IRioLRTOperatorRegistry.OperatorValidatorDetails memory validators;
        unchecked {
            uint8 i;
            for (i = 0; i < numActiveOperators; ++i) {
                uint8 operatorId = s.activeOperatorsByETHDepositUtilization.get(i);

                // Non-existent operator ID. We've reached the end of the heap.
                if (operatorId == 0) break;

                validators = s.operatorDetails[operatorId].validatorDetails;
                activeDeposits = validators.deposited - validators.exited;
                heap.operators[i + 1] = OperatorUtilizationHeap.Operator({
                    id: operatorId,
                    utilization: activeDeposits.divWad(validators.cap)
                });
            }
            heap.count = i;
        }
    }
```
as we can see, the heap is always assumed to be order in the storage when the registry fetches it initially. There are no ordering of the heap when requesting the heap initially.

When, say the deallocation happens via an user withdrawal request, the queue can exit early if the operator in the heap has "0" room:
```solidity
 function deallocateETHDeposits(uint256 depositsToDeallocate) external onlyCoordinator returns (uint256 depositsDeallocated, OperatorETHDeallocation[] memory deallocations) {
        deallocations = new OperatorETHDeallocation[](s.activeOperatorCount);


        OperatorUtilizationHeap.Data memory heap = s.getOperatorUtilizationHeapForETH();
        if (heap.isEmpty()) revert NO_AVAILABLE_OPERATORS_FOR_DEALLOCATION();


        uint256 deallocationIndex;
        uint256 remainingDeposits = depositsToDeallocate;


        bytes memory pubKeyBatch;
        while (remainingDeposits > 0) {
            uint8 operatorId = heap.getMax().id;


            OperatorDetails storage operator = s.operatorDetails[operatorId];
            OperatorValidatorDetails memory validators = operator.validatorDetails;
            -> uint256 activeDeposits = validators.deposited - validators.exited;


            // Exit early if the operator with the highest utilization rate has no active deposits,
            // as no further deallocations can be made.
            -> if (activeDeposits == 0) break;
             .
        }
        .
    }
```

`reportOutOfOrderValidatorExits` increases the "exited" part of the operators validator:
```solidity
function reportOutOfOrderValidatorExits(uint8 operatorId, uint256 fromIndex, uint256 validatorCount) external {
       .
       .
        // Swap the position of the validators starting from the `fromIndex` with the validators that were next in line to be exited.
        VALIDATOR_DETAILS_POSITION.swapValidatorDetails(operatorId, fromIndex, validators.exited, validatorCount);
        -> operator.validatorDetails.exited += uint40(validatorCount);

        emit OperatorOutOfOrderValidatorExitsReported(operatorId, validatorCount);
    }
```

Now, knowing all these above, let's do an example where calling `reportOutOfOrderValidatorExits` can make the heap work wrongly and exit prematurely.

Assume there are 3 operators which has native ETH deposits. 
operatorId 1 -> utilization 5%
operatorId 2 -> utilization 10%
operatorId 3 -> utilization 15%

such operators would be ordered in the heap as:
heap.operators[1] -> operatorId: 1, utilization: 5
heap.operators[2] -> operatorId: 2, utilization: 10
heap.operators[3] -> operatorId: 3, utilization: 15
heap.getMin() -> operatorId: 1, utilization: 5
heap.getMax() -> operatorId:3, utilization 15

now, let's say the "cap" is 100 for all of the operators which means that:
operatorId 1 -> validator.deposits = 5, validator.exit = 0
operatorId 2 -> validator.deposits = 10, validator.exit = 0
operatorId 3 -> validator.deposits = 15, validator.exit = 0

Let's assume that the operator 3 exits 15 validator from beacon chain without prior to a user request, which is a reason for owner to call `reportOutOfOrderValidatorExits` to increase the exited validators. 

When the owner calls `reportOutOfOrderValidatorExits` for the operatorId 3, the exited will be 15 for the operatorId 3. 
After the call the operators validator balances will be:
operatorId 1 -> validator.deposits = 5, validator.exit = 0
operatorId 2 -> validator.deposits = 10, validator.exit = 8
operatorId 3 -> validator.deposits = 15, validator.exit = 15

hence, the utilizations will be:
operatorId 1 -> utilization 5%
operatorId 2 -> utilization 10%
operatorId 3 -> utilization 0%

which means now the operatorId 3 has the lowest utilization and should be the first to get deposits and last to unwind deposits from. However, the heap is not re-ordered meaning that the minimum in the heap is  still opeartorId 1 and the maximum is still operatorId 3!

Now, when a user tries to withdraw, the first deallocation target will be the operatorId 3 because the heap thinks that it is the most utilized still. 

However, since the active utilization for operatorId 3 is "0" the loop will exit early hence, the withdrawals will not go through
https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTOperatorRegistry.sol#L556-L560

Hence, the user will not be able to request the withdrawal! 

**Coded PoC:**
```solidity
// forge test --match-contract OperatorUtilizationHeapTest --match-test test_RemovingValidatorMessesTheHeap -vv
    function test_RemovingValidatorMessesTheHeap() public {
        OperatorUtilizationHeap.Data memory heap = OperatorUtilizationHeap.initialize(5);

        // @review initialize and order 3 operators 
        heap.insert(OperatorUtilizationHeap.Operator({id: 1, utilization: 5}));
        heap.store(heapStore);

        heap.insert(OperatorUtilizationHeap.Operator({id: 2, utilization: 10}));
        heap.store(heapStore);

        heap.insert(OperatorUtilizationHeap.Operator({id: 3, utilization: 15}));
        heap.store(heapStore);

        // @review mimick how the heap can be fetched from the storage initially
        uint8 numActiveOperators = 3;
        OperatorUtilizationHeap.Data memory newHeap = OperatorUtilizationHeap.initialize(64);
        uint8 i;
        for (i = 0; i < numActiveOperators; ++i) {
            uint8 operatorId = heapStore.get(i);
            if (operatorId == 0) break;

            newHeap.operators[i+1] = OperatorUtilizationHeap.Operator({
                   id: operatorId,
                   utilization: heap.operators[operatorId].utilization
            });
        }
        newHeap.count = i;

        // @review assume the reportValidatorAndExits called, and now the utilization is "0"
        heap.updateUtilizationByID(3, 0);
        // @review this should be done, but the heap is not stored! 
        // heap.store(heapStore);

        console.log("1st", heap.operators[1].id);
        console.log("2nd", heap.operators[2].id);
        console.log("3rd", heap.operators[3].id);
        console.log("origin heaps min", heap.getMin().id);
        console.log("origin heaps max", heap.getMax().id);

        console.log("1st", newHeap.operators[1].id);
        console.log("2nd", newHeap.operators[2].id);
        console.log("3rd", newHeap.operators[3].id);
        console.log("new heaps min", newHeap.getMin().id);
        console.log("new heaps max", newHeap.getMax().id);

        // @review mins and maxs are mixed
        assertEq(newHeap.getMin().id, 1);
        assertEq(heap.getMin().id, 3);
        assertEq(heap.getMax().id, 2);
        assertEq(newHeap.getMax().id, 3);
    }
```
## Impact
Heap can be mixed, withdrawals and deposits can fail, hence I will label this as high. 
## Code Snippet
https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/utils/OperatorRegistryV1Admin.sol#L357C5-L386C6

https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTOperatorRegistry.sol#L541-L594

https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTOperatorRegistry.sol#L310-L336
## Tool used

Manual Review

## Recommendation
update the utilization in the reportOutOfOrderValidatorExits function 

# Issue M-1: Deposits to EigenLayer strategy from deposit pool can revert due to `maxPerDeposit` cap in the EigenLayer strategies 

Source: https://github.com/sherlock-audit/2024-02-rio-network-core-protocol-judging/issues/5 

## Found by 
g, hash, mstpr-brainbot
## Summary
The collected LSTs in the deposit pool are deposited to EigenLayer when a rebalance occurs. Rio contracts only check the total cap, but they don't verify the `maxPerDeposit` in the strategy contracts of EigenLayer. If the deposit exceeds the `maxPerDeposit` set in the strategy contract, the rebalancing will revert.
## Vulnerability Detail
Best to demonstrate this with an example, so let's proceed:

Suppose there is only one operator with one strategy in the Rio network, which is the stETH strategy. Users deposit a total of 500 stETH to the contract, which is directly sent to the deposit pool, as evident in the following snippet from the coordinator contract:

```solidity
function deposit(address asset, uint256 amountIn) external checkDeposit(asset, amountIn) returns (uint256 amountOut) {
        // Convert deposited asset amount to restaking tokens.
        amountOut = convertFromAssetToRestakingTokens(asset, amountIn);

        // Pull tokens from the sender to the deposit pool.
        // @review sends directly to depositPool which the funds are stay idle till the rebalancing happens
        -> IERC20(asset).safeTransferFrom(msg.sender, address(depositPool()), amountIn);

        // Mint restaking tokens to the caller.
        token.mint(msg.sender, amountOut);

        emit Deposited(msg.sender, asset, amountIn, amountOut);
    }
```
When the rebalance is called in the coordinator, it triggers the deposit pool to deposit its balance to the EigenLayer. For the sake of this example, let's assume there are no withdrawals queued in the epoch. The following snippet will be called in the deposit pool:
```solidity
function depositBalanceIntoEigenLayer(address asset) external onlyCoordinator returns (uint256, bool) {
        .
        .
        address strategy = assetRegistry().getAssetStrategy(asset);
        uint256 sharesToAllocate = assetRegistry().convertToSharesFromAsset(asset, amountToDeposit);
        -> return (OperatorOperations.depositTokenToOperators(operatorRegistry(), asset, strategy, sharesToAllocate), isDepositCapped);
    }
```

As seen in the above snippet, the `OperatorOperations` library contract is called to deposit the stETH to operators (assuming there is only one in this example). Since there is only one operator, all the shares will be allocated to the stETH strategy, and the `stakeERC20` function will be called in the `OperatorOperations`, which does the following:

```solidity
function stakeERC20(address strategy, address token_, uint256 amount) external onlyDepositPool returns (uint256 shares) {
        if (IERC20(token_).allowance(address(this), address(strategyManager)) < amount) {
            IERC20(token_).forceApprove(address(strategyManager), type(uint256).max);
        }
        // @review deposits all the tokens to strategy
        -> shares = strategyManager.depositIntoStrategy(strategy, token_, amount);
    }
```

As observed above, all the funds are directly sent to the strategy for deposit. Inside the strategy manager contract from EigenLayer, there is a `_beforeDeposit` hook that checks the deposit amount and performs some validations:


```solidity
function _beforeDeposit(IERC20 token, uint256 amount) internal virtual override {
        require(amount <= maxPerDeposit, "StrategyBaseTVLLimits: max per deposit exceeded");
        require(_tokenBalance() <= maxTotalDeposits, "StrategyBaseTVLLimits: max deposits exceeded");

        super._beforeDeposit(token, amount);
    }
```

As seen, the deposited amount is checked to see whether it exceeds the `maxPerDeposit` allowed or not, which is not related to the total cap. In our example, if we were depositing 500 stETH and the `maxPerDeposit` is less than 500 stETH, the call will revert, making rebalancing impossible.

## Impact
Rebalance would revert. However, the owner can set the operators cap to maxPerDeposit and call rebalance quickly and then sets the cap back to normal. However, this would only solve the issue temporarily and can be frontrunned. I am not sure how to label this, will go for medium.
## Code Snippet
https://github.com/sherlock-audit/2024-02-rio-vesting-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTCoordinator.sol#L77-L88

https://github.com/sherlock-audit/2024-02-rio-vesting-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTCoordinator.sol#L121-L151

https://github.com/sherlock-audit/2024-02-rio-vesting-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTDepositPool.sol#L47-L67

https://github.com/sherlock-audit/2024-02-rio-vesting-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/utils/OperatorOperations.sol#L51-L68

https://github.com/sherlock-audit/2024-02-rio-vesting-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTOperatorRegistry.sol#L342-L392

https://github.com/sherlock-audit/2024-02-rio-vesting-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTOperatorDelegator.sol#L174-L179

https://github.com/Layr-Labs/eigenlayer-contracts/blob/5c192e1a780c22e027f6861f958db90fb9ae263c/src/contracts/core/StrategyManager.sol#L323-L342

https://github.com/Layr-Labs/eigenlayer-contracts/blob/5c192e1a780c22e027f6861f958db90fb9ae263c/src/contracts/core/StrategyManager.sol#L105-L111

https://github.com/Layr-Labs/eigenlayer-contracts/blob/5c192e1a780c22e027f6861f958db90fb9ae263c/src/contracts/strategies/StrategyBaseTVLLimits.sol#L79-L84
## Tool used

Manual `Review`

## Recommendation
Check the `maxPerDeposit` in the strategy contract and cap the deposits to EigenLayer to that amount



## Discussion

**solimander**

Originally, we didn't want to add the gas overhead as we may not deploy ERC20 strategies until caps are removed, but I'm considering this one. Feels like it may be worth adding regardless.

# Issue M-2: Depositing to EigenLayer can revert due to round downs in converting shares<->assets 

Source: https://github.com/sherlock-audit/2024-02-rio-network-core-protocol-judging/issues/9 

## Found by 
0xkaden, Bauer, Drynooo, KupiaSec, Tricko, hash, kennedy1030, klaus, lemonmon, mstpr-brainbot, shaka
## Summary
When the underlying tokens deposited from depositPool to EigenLayer strategy, there are bunch of converting operations done which rounds down the solution at some point and the require check reverts hence, the depositing might not be possible due to this small round down issue. 
## Vulnerability Detail
Best to go for this is an example, so let's do it.

Assume the deposit pool has 111 * 1e18 stETH waiting for rebalance to be deposited to EigenLayer and there is only 1 operator with 1 strategy allowed which is the EigenLayers stETH strategy. 
Also, assume the EigenLayer has 3333 * 1e18 stETH in total and 3232  * 1e18 shares in supply. Also, note that the EigenLayer uses virtual shares offset which is 1e3.

Now, let's say there is no withdrawal queue to ease the complexity of the issue and rebalance is called and the balance in the deposit pool will be forwarded to EigenLayer strategy as follows:
```solidity
function rebalance(address asset) external checkRebalanceDelayMet(asset) {
        .
        .
        // Deposit remaining assets into EigenLayer.
        (uint256 sharesReceived, bool isDepositCapped) = depositPool().depositBalanceIntoEigenLayer(asset);
        .
    }
```

Then, the `depositBalanceIntoEigenLayer` will trigger the `OperatorOperations.depositTokenToOperators` function as follows:
```solidity 
function depositBalanceIntoEigenLayer(address asset) external onlyCoordinator returns (uint256, bool) {
        uint256 amountToDeposit = asset.getSelfBalance();
        if (amountToDeposit == 0) return (0, false);
        .
        .
        address strategy = assetRegistry().getAssetStrategy(asset);
        uint256 sharesToAllocate = assetRegistry().convertToSharesFromAsset(asset, amountToDeposit);
        // @review library called
        -> return (OperatorOperations.depositTokenToOperators(operatorRegistry(), asset, strategy, sharesToAllocate), isDepositCapped);
    }
```
As we can see in the above snippet, the underlying tokens to be deposited which is 111 * 1e18 stETH in our example will be converted to EigenLayer strategy shares via `assetRegistry().convertToSharesFromAsset`

Now, how does EigenLayer calculates how much shares to be minted given an underlying token deposit is as follows:
```solidity
function underlyingToSharesView(uint256 amountUnderlying) public view virtual returns (uint256) {
        // account for virtual shares and balance
        uint256 virtualTotalShares = totalShares + SHARES_OFFSET;
        uint256 virtualTokenBalance = _tokenBalance() + BALANCE_OFFSET;
        // calculate ratio based on virtual shares and balance, being careful to multiply before dividing
        return (amountUnderlying * virtualTotalShares) / virtualTokenBalance;
    }
```

Now, let's plugin our numbers in the example to calculate how much shares would be minted according to EigenLayer:
`virtualTotalShares` = 3232 * 1e18 + 1e3
`virtualTokenBalance` = 3333 * 1e18 + 1e3
`amountUnderlying` = 111 * 1e18

**and when we do the math we will calculate the shares to be minted as:
107636363636363636364**

Then, the library function will be executed as follows:
```solidity
function depositTokenToOperators(
        IRioLRTOperatorRegistry operatorRegistry,
        address token,
        address strategy,
        uint256 sharesToAllocate // @review 107636363636363636364 as we calculated above!
    ) internal returns (uint256 sharesReceived) {
        (uint256 sharesAllocated, IRioLRTOperatorRegistry.OperatorStrategyAllocation[] memory  allocations) = operatorRegistry.allocateStrategyShares(
            strategy, sharesToAllocate
        );

        for (uint256 i = 0; i < allocations.length; ++i) {
            IRioLRTOperatorRegistry.OperatorStrategyAllocation memory allocation = allocations[i];

            IERC20(token).safeTransfer(allocation.delegator, allocation.tokens);
            sharesReceived += IRioLRTOperatorDelegator(allocation.delegator).stakeERC20(strategy, token, allocation.tokens);
        }
        if (sharesReceived != sharesAllocated) revert INCORRECT_NUMBER_OF_SHARES_RECEIVED();
    }
```

The very first line of the above snippet executes the `operatorRegistry.allocateStrategyShares`, let's examine that:
```solidity
 function allocateStrategyShares(address strategy, uint256 sharesToAllocate) external onlyDepositPool returns (uint256 sharesAllocated, OperatorStrategyAllocation[] memory allocations) {
        .
        uint256 remainingShares = sharesToAllocate;
        allocations = new OperatorStrategyAllocation[](s.activeOperatorCount);
        while (remainingShares > 0) {
            .
            .
            uint256 newShareAllocation = FixedPointMathLib.min(operatorShares.cap - operatorShares.allocation, remainingShares);
            uint256 newTokenAllocation = IStrategy(strategy).sharesToUnderlyingView(newShareAllocation);
            allocations[allocationIndex] = OperatorStrategyAllocation(
                operator.delegator,
                newShareAllocation,
                newTokenAllocation
            );
            remainingShares -= newShareAllocation;
            .
            .
        }
        sharesAllocated = sharesToAllocate - remainingShares;
        .
        .
    }
```

So, let's value the above snippet aswell considering the cap is not reached. As we can see the how much underlying token needed is again calculated by querying the EigenLayer strategy `sharesToUnderlyingView`, so let's first calculate that:
```solidity
function sharesToUnderlyingView(uint256 amountShares) public view virtual override returns (uint256) {
        // account for virtual shares and balance
        uint256 virtualTotalShares = totalShares + SHARES_OFFSET;
        uint256 virtualTokenBalance = _tokenBalance() + BALANCE_OFFSET;
        // calculate ratio based on virtual shares and balance, being careful to multiply before dividing
        return (virtualTokenBalance * amountShares) / virtualTotalShares;
    }
```
Let's put the values to above snippet:
`virtualTotalShares` = 3232 * 1e18 + 1e3
`virtualTokenBalance` = 3333 * 1e18 + 1e3
`amountShares` = 107636363636363636364
**hence, the return value is 110999999999999999999(as you noticed it is not 111 * 1e18 as we expect!)**

`sharesToAllocate` =  remainingShares  = newShareAllocation  = 107636363636363636364
`newTokenAllocation` = 110999999999999999999
`sharesAllocated` = 107636363636363636364

Now, let's go back to `depositTokenToOperators` function and move with the execution flow:

as we can see the underlying tokens we calculated (110999999999999999999) is deposited to EigenLayer for shares here and then compared in the last line in the if check as follows:
```solidity
for (uint256 i = 0; i < allocations.length; ++i) {
            IRioLRTOperatorRegistry.OperatorStrategyAllocation memory allocation = allocations[i];

            IERC20(token).safeTransfer(allocation.delegator, allocation.tokens);
            sharesReceived += IRioLRTOperatorDelegator(allocation.delegator).stakeERC20(strategy, token, allocation.tokens);
        }
        if (sharesReceived != sharesAllocated) revert INCORRECT_NUMBER_OF_SHARES_RECEIVED();
```

`stakeERC20` will stake 110999999999999999999 tokens and in exchange **will receive 107636363636363636363** shares. Then the `sharesReceived` will be compared with the **initial share amount calculation which is 107636363636363636364**

**hence, the last if check will revert because
107636363636363636363 != 107636363636363636364**

**Coded PoC:**
```solidity
function test_RioRoundingDownPrecision() external pure returns (uint, uint) {
        uint underlyingTokens = 111 * 1e18;
        uint totalUnderlyingTokensInEigenLayer = 3333 * 1e18;
        uint totalSharesInEigenLayer = 3232 * 1e18;
        uint SHARE_AND_BALANCE_OFFSET = 1e3;

        uint virtualTotalShares =  totalSharesInEigenLayer + SHARE_AND_BALANCE_OFFSET;
        uint virtualTokenBalance = totalUnderlyingTokensInEigenLayer + SHARE_AND_BALANCE_OFFSET;

        uint underlyingTokensToEigenLayerShares = (underlyingTokens * virtualTotalShares) / virtualTokenBalance;
        uint eigenSharesToUnderlying = (virtualTokenBalance * underlyingTokensToEigenLayerShares) / virtualTotalShares;

        // we expect eigenSharesToUnderlying == underlyingTokens, which is not
        require(eigenSharesToUnderlying != underlyingTokens);

        return (underlyingTokensToEigenLayerShares, eigenSharesToUnderlying);
    }
```
## Impact
The issue described above can happen frequently as long as the perfect division is not happening when converting shares/assets. In order to solve the issue the amounts and shares has to be perfectly divisible such that the rounding down is not an issue. This can be fixed by owner to airdrop some assets such that this is possible. However, considering how frequent and easy the above scenario can happen and owner needs to do some math to fix the issue, I'll label this as high.
## Code Snippet
https://github.com/sherlock-audit/2024-02-rio-vesting-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTDepositPool.sol#L47-L67

https://github.com/sherlock-audit/2024-02-rio-vesting-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTAssetRegistry.sol#L215-L221

https://github.com/Layr-Labs/eigenlayer-contracts/blob/5c192e1a780c22e027f6861f958db90fb9ae263c/src/contracts/strategies/StrategyBase.sol#L211-L243

https://github.com/sherlock-audit/2024-02-rio-vesting-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/utils/OperatorOperations.sol#L51-L68

https://github.com/sherlock-audit/2024-02-rio-vesting-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTOperatorRegistry.sol#L342-L392

https://github.com/sherlock-audit/2024-02-rio-vesting-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTOperatorDelegator.sol#L174-L179
## Tool used

Manual Review

## Recommendation

# Issue M-3: AssetRegistry owner can be frontrunned when removing asset 

Source: https://github.com/sherlock-audit/2024-02-rio-network-core-protocol-judging/issues/15 

## Found by 
Avci, HSP, PNS, aslanbek, cats, deth, merlin, mstpr-brainbot, popular
## Summary
The AssetRegistry owner can remove an asset at any time, provided that certain checks are satisfied. One of these checks is that the TVL for the asset must be "0". This implies that the asset should not exist in the system at all, neither in the deposit pool nor in the EigenLayer strategy. However, anyone can donate 1 wei of the asset to the deposit pool address to grief the owner, and the owner cannot do anything to prevent it.
## Vulnerability Detail
This is the validation checks in the `removeAsset` function implemented:

```solidity
function removeAsset(address asset) external onlyOwner {
        if (!isSupportedAsset(asset)) revert ASSET_NOT_SUPPORTED(asset);
        // @review someone can donate 1 wei to grief here
        -> if (getTVLForAsset(asset) > 0) revert ASSET_HAS_BALANCE();
        .
    }
```

now let's also check how `getTVLForAsset` function is implemented:

```solidity
function getTVLForAsset(address asset) public view returns (uint256) {
        uint256 balance = getTotalBalanceForAsset(asset);
        if (asset == ETH_ADDRESS) {
            return balance;
        }
        return convertToUnitOfAccountFromAsset(asset, balance);
    }

function getTotalBalanceForAsset(address asset) public view returns (uint256) {
        .
        .
        -> uint256 tokensInRio = IERC20(asset).balanceOf(depositPool_);
        uint256 tokensInEigenLayer = convertFromSharesToAsset(getAssetStrategy(asset), sharesHeld);

        return tokensInRio + tokensInEigenLayer;
    }
```

as we can observe, `tokensInRio` variable is the `IERC20.balanceOf` call result which means that if anyone donates 1 wei of the asset to deposit pool just before the owners `removeAsset` tx, then the tx will revert.

**Another scenario from same root cause:**
Since every LRT gets a sacrificial deposit in the deployment phrase, there will be always some excess tokens that are not possible to be burnt because the coordinator can't burn the LRT tokens received in deployment. 
## Impact
Very cheap to execute the attack (1 wei of token) and can be called simply even every block to grief owner if really wanted.
## Code Snippet
https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTAssetRegistry.sol#L250C5-L263C6

https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTAssetRegistry.sol#L79-L102

## Tool used

Manual Review

## Recommendation



## Discussion

**nevillehuang**

Borderline medium/low, need @Czar102 opinion, see similar [finding here](https://github.com/sherlock-audit/2023-12-ubiquity-judging/issues/14#issuecomment-1941398707)

**solimander**

Technically valid. May just drop asset removals in this version.

**nevillehuang**

I think this falls under the following category so leaving as medium severity, given users can easily prevent removal of assets

> 1. The issue causes locking of funds for users for more than a week.

# Issue M-4: If the operators receives or tries to deposit dust amount of shares then the rebalance will not be possible 

Source: https://github.com/sherlock-audit/2024-02-rio-network-core-protocol-judging/issues/18 

## Found by 
almurhasan, fnanni, mstpr-brainbot
## Summary
Operators has caps when depositing to the strategies of EigenLayer. If the deposited amount is dust then the round down of the shares minted can be "0" which the tx would revert in EigenLayer side. This would brick the deposit and rebalance flow completely. 
## Vulnerability Detail
When the deposit pool has excess balance, the balance will be distributed to operators respecting their utilizations and caps. Assume the least utilized operator has only a few remaining spots left, which is a dust amount like 1e3. Now, let's see what would happen in the allocation flow:
```solidity
function allocateStrategyShares(address strategy, uint256 sharesToAllocate) external onlyDepositPool returns (uint256 sharesAllocated, OperatorStrategyAllocation[] memory allocations) {
        .
        while (remainingShares > 0) {
            .
            .
           -> uint256 newShareAllocation = FixedPointMathLib.min(operatorShares.cap - operatorShares.allocation, remainingShares);
            -> uint256 newTokenAllocation = IStrategy(strategy).sharesToUnderlyingView(newShareAllocation);
            allocations[allocationIndex] = OperatorStrategyAllocation(
                operator.delegator,
                newShareAllocation,
                newTokenAllocation
            );
            .
            .
        }
       .
    }
```

As we can observe in the above snippet, if the amount is dust, then `uint256 newTokenAllocation = IStrategy(strategy).sharesToUnderlyingView(newShareAllocation);` can be rounded down to "0" since EigenLayer rounds down when calculating the underlying tokens needed. Then, the `newTokenAllocation` will be equal to "0", and the delegation operator deposits the amount to EigenLayer as follows:

```solidity
function stakeERC20(address strategy, address token_, uint256 amount) external onlyDepositPool returns (uint256 shares) {
        if (IERC20(token_).allowance(address(this), address(strategyManager)) < amount) {
            IERC20(token_).forceApprove(address(strategyManager), type(uint256).max);
        }
        -> shares = strategyManager.depositIntoStrategy(strategy, token_, amount);
    }
```

From the above snippet, we can see that the `strategyManager.depositIntoStrategy` will be called with an amount of "0". Now, let's examine how EigenLayer handles the "0" amount deposits:

```solidity
function deposit(
        IERC20 token,
        uint256 amount
    ) external virtual override onlyWhenNotPaused(PAUSED_DEPOSITS) onlyStrategyManager returns (uint256 newShares) {
        .
        .
        // account for virtual shares and balance
        uint256 virtualShareAmount = priorTotalShares + SHARES_OFFSET;
        uint256 virtualTokenBalance = _tokenBalance() + BALANCE_OFFSET;
        // calculate the prior virtual balance to account for the tokens that were already transferred to this contract
        uint256 virtualPriorTokenBalance = virtualTokenBalance - amount;
        newShares = (amount * virtualShareAmount) / virtualPriorTokenBalance;

        // extra check for correctness / against edge case where share rate can be massively inflated as a 'griefing' sort of attack
        -> require(newShares != 0, "StrategyBase.deposit: newShares cannot be zero");
        .
    }
```

As we can see, if the shares to be minted are "0," which will be the case since we try to deposit "0" amount of tokens, then the transaction will revert, hence, the entire deposit flow will be halted.

Malicious Scenario:
Assume that at an epoch, there are "N" assets requested for withdrawal, and there are no deposits to the LRT token. The attacker can donate 1 wei to the deposit pool just before the rebalance call. Subsequently, the rebalance would attempt to withdraw the "N" tokens as normal. However, when it tries to deposit the excess back to operators, which is only "1 wei," the transaction can revert since it's a dust amount.
## Impact
The above scenarios can happen in normal flow or can be triggered by a malicious user. There is a DoS threat and it needs donations or owner manually lowering the caps. Hence, I will label this as medium.
## Code Snippet
https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTOperatorRegistry.sol#L342-L392

https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTOperatorDelegator.sol#L174-L179

https://github.com/Layr-Labs/eigenlayer-contracts/blob/5c192e1a780c22e027f6861f958db90fb9ae263c/src/contracts/strategies/StrategyBase.sol#L96-L123
## Tool used

Manual Review

## Recommendation
If the amount is dust then skip to the next operator and ignore the amount, don't deposit. 



## Discussion

**nevillehuang**

request poc

Given there is a sacrificial deposit, wouldn't this be not possible?

**sherlock-admin3**

PoC requested from @mstpr

Requests remaining: **18**

**mstpr**


PoC:
```solidity
// forge test --match-contract RioLRTDepositPoolTest --match-test test_RoundDownInEigenLayerStrategy -vv
 function test_RoundDownInEigenLayerStrategy() public {
        uint8 operatorId = addOperatorDelegator(reLST.operatorRegistry, address(reLST.rewardDistributor));
        address operatorDelegator = reLST.operatorRegistry.getOperatorDetails(operatorId).delegator;

        // initiate the strategy with some funds first
        uint bootstrapAm = 100 * 1e18;
        cbETH.mint(EOA, bootstrapAm);
        uint256 AMOUNT = 1;
        vm.prank(EOA);
        cbETH.approve(address(strategyManager), type(uint256).max);
        vm.prank(EOA);
        strategyManager.depositIntoStrategy(address(CBETH_STRATEGY), CBETH_ADDRESS, bootstrapAm);
        // add some more cbETH to mock yield on the strategy
        cbETH.mint(address(CBETH_STRATEGY), 1e5);

        uint sharess = IStrategy(CBETH_STRATEGY).underlyingToSharesView(AMOUNT);
        // round down to "0" as we expected!
        assertEq(sharess, 0);

        // Allocate to cbETH strategy.small amount such that the amount round down in EigenLayer strategy and it reverts
        cbETH.approve(address(reLST.coordinator), type(uint256).max);
        reLST.coordinator.deposit(CBETH_ADDRESS, AMOUNT);
        console.log("SHARES HELD", reLST.assetRegistry.getAssetSharesHeld(CBETH_ADDRESS));

        // Push funds into EigenLayer, it will fail because of the 
        vm.startPrank(EOA, EOA);
        vm.expectRevert();
        reLST.coordinator.rebalance(CBETH_ADDRESS);
        vm.stopPrank();
    }
```

**mstpr**

> request poc
> 
> Given there is a sacrificial deposit, wouldn't this be not possible?



> request poc
> 
> Given there is a sacrificial deposit, wouldn't this be not possible?

Not really. This round down issue happens in EigenLayer strategy side not in Rio's. 

**solimander**

I don't believe this is feasible when there are actually pending withdrawals.

e.g.

```solidity
function test_RoundDownInEigenLayerStrategy() public {
    uint8 operatorId = addOperatorDelegator(reLST.operatorRegistry, address(reLST.rewardDistributor));
    address operatorDelegator = reLST.operatorRegistry.getOperatorDetails(operatorId).delegator;

    // initiate the strategy with some funds first
    uint256 bootstrapAm = 100 * 1e18;
    cbETH.mint(EOA, bootstrapAm);
    uint256 AMOUNT = 1;
    vm.prank(EOA);
    cbETH.approve(address(strategyManager), type(uint256).max);
    vm.prank(EOA);

    strategyManager.depositIntoStrategy(address(CBETH_STRATEGY), CBETH_ADDRESS, bootstrapAm);

    cbETH.approve(address(reLST.coordinator), type(uint256).max);

    // Deposit to create some reLST to withdraw
    cbETH.mint(address(CBETH_STRATEGY), 1e18);
    uint256 amountOut = reLST.coordinator.deposit(CBETH_ADDRESS, 1e18);

    // Rebalance to push into EigenLayer
    skip(reLST.coordinator.rebalanceDelay());

    vm.prank(EOA, EOA);
    reLST.coordinator.rebalance(CBETH_ADDRESS);

    reLST.coordinator.requestWithdrawal(CBETH_ADDRESS, amountOut);

    // add some more cbETH to mock yield on the strategy
    cbETH.mint(address(CBETH_STRATEGY), 1e5);

    uint256 sharess = IStrategy(CBETH_STRATEGY).underlyingToSharesView(AMOUNT);
    // round down to "0" as we expected!
    assertEq(sharess, 0);

    // Allocate to cbETH strategy.small amount such that the amount round down in EigenLayer strategy and it reverts
    reLST.coordinator.deposit(CBETH_ADDRESS, AMOUNT);
    console.log('SHARES HELD', reLST.assetRegistry.getAssetSharesHeld(CBETH_ADDRESS));

    skip(reLST.coordinator.rebalanceDelay());

    vm.startPrank(EOA, EOA);
    vm.expectRevert();
    reLST.coordinator.rebalance(CBETH_ADDRESS);
    vm.stopPrank();
}
```

# Issue M-5: Ether can stuck when an operators validators are removed due to an user front-running 

Source: https://github.com/sherlock-audit/2024-02-rio-network-core-protocol-judging/issues/45 

## Found by 
hash, mstpr-brainbot, zzykxx
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



## Discussion

**nevillehuang**

Borderline Medium/Low, leaving open for discussion. I think I agree with watsons, unless there is someway to retrieve the potentially locked ETH.

**solimander**

Accepted risk of design, though considering adding an emergency scrape function to avoid the possible annoyance.

**nevillehuang**

I believe this risk should have been mentioned in contest details, so leaving as medium severity.

# Issue M-6: A part of ETH rewards can be stolen by sandwiching `claimDelayedWithdrawals()` 

Source: https://github.com/sherlock-audit/2024-02-rio-network-core-protocol-judging/issues/52 

## Found by 
araj, aslanbek, cats, giraffe, pontifex, zzykxx
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

# Issue M-7: Requested withdrawal can be impossible to settle due to EigenLayer shares value appreciate when there are idle funds in deposit pool 

Source: https://github.com/sherlock-audit/2024-02-rio-network-core-protocol-judging/issues/109 

## Found by 
Audinarey, Aymen0909, Bauer, Bony, Drynooo, cats, deepplus, g, hash, kennedy1030, monrel, mstpr-brainbot, peanuts, sakshamguruji, shaka, zzykxx
## Summary
When users request a withdrawal, the EigenLayer shares equivalent to their LRT's value are recorded. During settlement, these EigenLayer shares must be deducted to finalize the withdrawal epoch. However, in certain scenarios, the requested EigenLayer shares may be impossible to unwind due to funds idling in the deposit pool. 
## Vulnerability Detail
Let's assume that 1 LRT equals 1 EigenLayer-cbETH, which equals 1 cbETH initially.

Alice deposits 5e18 cbETH, and her deposits are allocated to operators after rebalancing. Now, Rio holds 5 EigenLayer-cbETH, which is worth 5 cbETH.

After some time, Bob deposits 100e18 cbETH to Rio and immediately withdraws it. At the time Bob requests this withdrawal, 100 cbETH is worth 100 EigenLayer-cbETH, so the shares owed are 100 EigenLayer-cbETH. At settlement, 100 EigenLayer-cbETH worth of cbETH has to be sent to the withdrawal queue to settle this epoch.

Now, assume that the value of EigenLayer-cbETH increases, meaning that 1 EigenLayer-cbETH is now worth more cbETH. This is an expected behavior because EigenLayer-cbETH is similar to an ERC4626 vault, and we expect its value to increase over time.

Let's say 1 EigenLayer-cbETH is now worth 1.1 cbETH.

Now, 100 cbETH sits idle in the deposit pool, and there are 5 EigenLayer-cbETH in the operators, which means there are a total of 90.9 + 5 = 95.9 EigenLayer-cbETH worth of cbETH in Rio. However, Bob's withdrawal request is for 100 EigenLayer-cbETH.

This would mean that Bob's withdrawal request will not be settled, and the entire withdrawal flow will be stuck because this epoch can't be settled.



**Coded PoC:**
```solidity
 // forge test --match-contract RioLRTDepositPoolTest --match-test test_InsufficientSharesInWithdrawal -vv
    function test_InsufficientSharesInWithdrawal() public {
        uint8 operatorId = addOperatorDelegator(reLST.operatorRegistry, address(reLST.rewardDistributor));
        address operatorDelegator = reLST.operatorRegistry.getOperatorDetails(operatorId).delegator;

        uint256 AMOUNT = 5e18;

        // Allocate to cbETH strategy.
        cbETH.approve(address(reLST.coordinator), type(uint256).max);
        reLST.coordinator.deposit(CBETH_ADDRESS, AMOUNT);
        console.log("SHARES HELD", reLST.assetRegistry.getAssetSharesHeld(CBETH_ADDRESS));

        // Push funds into EigenLayer.
        vm.prank(EOA, EOA);
        reLST.coordinator.rebalance(CBETH_ADDRESS);

        assertEq(cbETH.balanceOf(address(reLST.depositPool)), 0);
        assertEq(reLST.assetRegistry.getAssetSharesHeld(CBETH_ADDRESS), AMOUNT);
        console.log("SHARES HELD", reLST.assetRegistry.getAssetSharesHeld(CBETH_ADDRESS));

        // @review before rebalance, deposit 100 * 1e18
        reLST.coordinator.deposit(CBETH_ADDRESS, 100e18);

        // @review request withdrawal 
        reLST.coordinator.requestWithdrawal(CBETH_ADDRESS, 100e18);
        console.log("SHARES HELD", reLST.assetRegistry.getAssetSharesHeld(CBETH_ADDRESS));

        // @review donate, the idea is to make EigenLayer shares worth more
        uint256 donate = 10_000 * 1e18;
        address tapir = address(69);
        MockERC20(CBETH_ADDRESS).mint(tapir, donate);
        console.log("before rate", reLST.assetRegistry.convertFromSharesToAsset(address(cbETHStrategy), 1e18));

        // @review expecting the rate to be higher after donation
        vm.prank(tapir);
        MockERC20(CBETH_ADDRESS).transfer(address(cbETHStrategy), donate);
        console.log("after rate", reLST.assetRegistry.convertFromSharesToAsset(address(cbETHStrategy), 1e18));

        // @review rebalance, expect revert
        skip(reLST.coordinator.rebalanceDelay());
        vm.startPrank(EOA, EOA);
        vm.expectRevert(bytes4(keccak256("INCORRECT_NUMBER_OF_SHARES_QUEUED()")));
        reLST.coordinator.rebalance(CBETH_ADDRESS);
        vm.stopPrank();
    }
```
## Impact
High since the further and current withdrawals are not possible. 
## Code Snippet
https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTCoordinator.sol#L99-L151

https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/utils/OperatorOperations.sol#L113-L134
## Tool used

Manual Review

## Recommendation



## Discussion

**solimander**

Seems unlikely to have a meaningful effect while rebasing tokens are not supported.

# Issue M-8: Partial withdrawals will decrease the LRT exchange rate 

Source: https://github.com/sherlock-audit/2024-02-rio-network-core-protocol-judging/issues/118 

## Found by 
mstpr-brainbot
## Summary
When the native staking validators are claimed via partial withdrawals from EigenPod the eigen pod shares will decrease whenever someone verifies the beacon chain balance of the validator. The rewards that are previously counted will decrease immediately hence, the exchange rate will change. 
## Vulnerability Detail
Assume that an operators validator has 34 ether in its validator where as 32 ether of it is the deposited part and the 2 ether is the reward. Also, the EigenPods balance is verified via [verifyBalanceUpdates](https://github.com/Layr-Labs/eigenlayer-contracts/blob/6de01c6c16d6df44af15f0b06809dc160eac0ebf/src/contracts/pods/EigenPod.sol#L185-L191) hence, the eigen pod shares that the operator has is 34 and its confirmed. 

Assume the validator decides to a partial withdrawal and claims the 2 ether from its beacon chain validator balance via [verifyAndProcessWithdrawals](https://github.com/Layr-Labs/eigenlayer-contracts/blob/6de01c6c16d6df44af15f0b06809dc160eac0ebf/src/contracts/pods/EigenPod.sol#L232-L239)

as we can see in the below snippet of **partial withdrawal**, there will be no shares difference which the EigenPod shares will not be updated after the `verifyAndProcessWithdrawals` call, however, the amount (2 ether in our case) will be sent to delayed router and can be claimed after the delay passes.
```solidity
function _processPartialWithdrawal(
        uint40 validatorIndex,
        uint64 withdrawalTimestamp,
        address recipient,
        uint64 partialWithdrawalAmountGwei
    ) internal returns (VerifiedWithdrawal memory) {
        emit PartialWithdrawalRedeemed(
            validatorIndex,
            withdrawalTimestamp,
            recipient,
            partialWithdrawalAmountGwei
        );

        sumOfPartialWithdrawalsClaimedGwei += partialWithdrawalAmountGwei;

        // For partial withdrawals, the withdrawal amount is immediately sent to the pod owner
        return
            VerifiedWithdrawal({
                amountToSendGwei: uint256(partialWithdrawalAmountGwei),
                sharesDeltaGwei: 0
            });
    }
```

```solidity
if (withdrawalSummary.amountToSendGwei != 0) {
            _sendETH_AsDelayedWithdrawal(podOwner, withdrawalSummary.amountToSendGwei * GWEI_TO_WEI);
        }
```

At this point, if someone calls `verifyBalanceUpdates` since the beacon chain of the validator has 32 ether now and previously it had 34 ether, the 2 ether excess will be decreased. Hence, the pod will have now 32 eigen pod shares. 

That means now the TVL has decreased by 2 ether until the delayed router claims and sends the ether back to the reward distributor contract. Also, note that the reward distributor contract not distributes the entire 2 ether to the deposit pool but some portion, so the recovered TVL will be lesser than 34 ether anyways. 

Conclusively, the ether balance will decrease 2 ether immediately and the exchange rate will be manipulated in this time window. All the functions such as deposit/withdrawals will be accounted mistakenly. 

**`Flow of the above scenario:`**
1- Operators validator receives 32 ether, and gets confirmed by the `verifyBalanceUpdates`, which EigenPodManager credits 32 shares.
2- After sometime, someone again calls `verifyBalanceUpdates` this time there are 34 ether due to rewards accrued from pos staking hence, an another 2 eigen pod shares credited, in total there are 34 eigen pod shares.
3- Validator does a partial withdrawal
4- Validator claims the 2 ether by partial withdrawal via `verifyAndProcessWithdrawals` this function sends the 2 ether to delayed router which can be claimed by operator delegator contract once the delay has passed. However, this function does not updates the eigen pod shares, which means the TVL is still 34 eigen pod shares
5- Someone proves the balance via `verifyBalanceUpdates` again and now since the validator has 32 ether, the excess 2 pod shares will be decreased and the TVL is now 32 eigen pod shares! 
6- The TVL decreased by 2 shares but in reality those 2 shares are the result of 2 ether claimed from rewards and they will be re-added to the contract balance after a delay. Decreasing the TVL here will manipulate the LRT exchange rate mistakenly since the 2 ether is not lost, they are just claimed and will be re-accounted soon.

## Impact
High, since the rewards will be claimed frequently and every time rewards are claimed the TVL will drop hence the exchange rate will be manipulated mistakenly. 
## Code Snippet
https://github.com/Layr-Labs/eigenlayer-contracts/blob/6de01c6c16d6df44af15f0b06809dc160eac0ebf/src/contracts/pods/EigenPod.sol#L185-L277
## Tool used

Manual Review

## Recommendation



## Discussion

**nevillehuang**

request poc

**sherlock-admin3**

PoC requested from @mstpr

Requests remaining: **17**

**solimander**

Don't see a large impact here, but will update to account for partial withdrawals earlier.

# Issue M-9: Execution Layer rewards are lost 

Source: https://github.com/sherlock-audit/2024-02-rio-network-core-protocol-judging/issues/174 

## Found by 
fnanni
## Summary

According to Rio Network Docs: "The Reward Distributor contract ([RioLRTRewardDistributor](https://github.com/contracts-and-tooling/source-code/restaking/riolrtrewarddistributor)) has the ability to [receive](https://github.com/contracts-and-tooling/source-code/restaking/riolrtrewarddistributor#receive) ETH via the Ethereum Execution Layer or EigenPod rewards and then distribute those rewards". However, this is only true for EigenPod rewards. Execution Layer rewards are not accounted for and lost.

## Vulnerability Detail

Execution Layer rewards are not distributed through plain ETH transfers. Instead the balance of the block proposer fee recipient's address is directly updated. If the fee recipient getting the EL rewards is a smart contract, this means that the fallback/receive function is not called. Actually, a smart contract could receive EL rewards even if these functions are not defined.

The [RioLRTRewardDistributor](https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTRewardDistributor.sol) contract relies solely on its [receive](https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTRewardDistributor.sol#L82-L94) function to distribute rewards. EL rewards which don't trigger this function are not accounted in the smart contract and there is no way of distributing them.

## Impact

Execution Layer rewards are lost.

## Code Snippet

## Tool used

Manual Review

## Recommendation

Add a method to manually distribute EL rewards. For example:

```solidity
    function distributeRemainingBalance() external {
        uint256 value = address(this).balance;

        uint256 treasuryShare = value * treasuryETHValidatorRewardShareBPS / MAX_BPS;
        uint256 operatorShare = value * operatorETHValidatorRewardShareBPS / MAX_BPS;
        uint256 poolShare = value - treasuryShare - operatorShare;

        if (treasuryShare > 0) treasury.transferETH(treasuryShare);
        if (operatorShare > 0) operatorRewardPool.transferETH(operatorShare);
        if (poolShare > 0) address(depositPool()).transferETH(poolShare);

        emit ETHValidatorRewardsDistributed(treasuryShare, operatorShare, poolShare);
    }
```



## Discussion

**nevillehuang**

request poc

I need more information/resources for this issue so need to facilitate discussion.

**sherlock-admin3**

PoC requested from @fnanni-0

Requests remaining: **6**

**fnanni-0**

@nevillehuang I forgot to link to the Rio docs: https://docs.rio.network/rio-architecture/deposits-and-withdraws/reward-distributor. Can we get @solimander input here? Reading this issue again, there is a chance I misunderstood the docs. Is the Reward Distributor contract expected to be able to receive Execution Layer rewards, i.e. be set as blocks fee_recipient address?

#### If the answer is yes:

From the [Solidity docs](https://docs.soliditylang.org/en/latest/contracts.html#receive-ether-function): "A contract without a receive Ether function can receive Ether as a recipient of a coinbase transaction". The recipient of a coinbase transaction post-merge is the address defined by the block proposer in the `fee_recipient` field of the [Execution Payload](https://github.com/ethereum/consensus-specs/blob/dev/specs/bellatrix/beacon-chain.md#executionpayload). According to https://eth2book.info/capella/annotated-spec/ : 

> fee_recipient is the Ethereum account address that will receive the unburnt portion of the transaction fees (the priority fees). This has been called various things at various times: the original Yellow Paper calls it beneficiary; [EIP-1559](https://eips.ethereum.org/EIPS/eip-1559) calls it author. In any case, the proposer of the block sets the fee_recipient to specify where the appropriate transaction fees for the block are to be sent. Under proof of work this was the same address as the COINBASE address that received the block reward. Under proof of stake, the block reward is credited to the validator's beacon chain balance, and **the transaction fees are credited to the fee_recipient Ethereum address**.

As an example go to etherscan and select any block recently produced. Check the fee recipient address. Check how its ETH balance is updated ("credited") at every transaction included in the block even though there is no explicit transaction to the fee recipient address (for example, balance update of beaverbuild [here](https://etherscan.io/tx/0xd6460ce006ff7d88d361fd2b08555e5e033208c187a16407f3a3bff304dd982d#statechange)).

**solimander**

Our operators will run MEV-Boost, which sets the fee recipient to the builder, who then transfers rewards to the proposer, which triggers the receive function.

However, it seems worth adding a function to manually push rewards just in case. How does that affect severity here?

**fnanni-0**

@solimander I have a few questions:

1. If mev-boost isn't available for a given block (for example there's a timeout), doesn't mev-boost fallback to a validator's local block proposal? See [this comment](https://github.com/flashbots/mev-boost/issues/222#issuecomment-1202401149) about Teku's client for instance (or Teku's [docs](https://docs.teku.consensys.io/concepts/builder-network#mev-boost)). In such case, fee_recipient would be the proposer address, not the builder's address.
2. The flow you described is the current standarized payment method for mev-boost. I wonder if this could change or if there are other builder networks handling this differently. If so, I think it's risky to assume that the proposer address will always receive rewards through direct transfers.
3. Isn't it likely that Ethereum upgrades in the future to better support Proposer-Builder Separation? If this happens, there's a chance the proposer address gets credited, not triggering the receive function.

**solimander**

> If mev-boost isn't available for a given block (for example there's a timeout), doesn't mev-boost fallback to a validator's local block proposal? See https://github.com/flashbots/mev-boost/issues/222#issuecomment-1202401149 about Teku's client for instance (or Teku's [docs](https://docs.teku.consensys.io/concepts/builder-network#mev-boost)). In such case, fee_recipient would be the proposer address, not the builder's address.

I'm unsure, but that'd make sense. I'll be adding a function to manually split and push rewards regardless.

**nevillehuang**

This issue seems out of scope and hinges on external admin integrations. But leaving open for escalation period

**sherlock-admin4**

The protocol team fixed this issue in PR/commit https://github.com/rio-org/rio-sherlock-audit/pull/6.

# Issue M-10: The protocol can't receive rewards because of low gas limits on ETH transfers 

Source: https://github.com/sherlock-audit/2024-02-rio-network-core-protocol-judging/issues/185 

## Found by 
0xkaden, Anubis, MatricksDeCoder, Topmark, Tricko, boredpukar, cats, deth, fnanni, hash, klaus, popular, sakshamguruji, zzykxx
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



## Discussion

**sherlock-admin4**

The protocol team fixed this issue in PR/commit https://github.com/rio-org/rio-sherlock-audit/pull/4.

# Issue M-11: RioLRTIssuer::issueLRT reverts if deposit asset's approve method doesn't return a bool 

Source: https://github.com/sherlock-audit/2024-02-rio-network-core-protocol-judging/issues/189 

## Found by 
fibonacci, fugazzi
## Summary

Using `ERC20::approve` will not work with ERC20 tokens that do not return a bool.

## Vulnerability Detail

The contest's README states that tokens that may not return a bool on ERC20 methods (e.g., USDT) are supposed to be used.

The `RioLRTIssuer::issueLRT` function makes a sacrificial deposit to prevent inflation attacks. To process the deposit, it calls the `ERC20::approve` method, which is expected to return a bool value.

Solidity has return data length checks, and if the token implementation does not return a bool value, the transaction will revert.

## Impact

Issuing LRT tokens with an initial deposit in an asset that does not return a bool on an `approve` call will fail.

## POC

Add this file to the `test` folder. Run test with `forge test --mc POC --rpc-url=<mainnet-rpc-url> -vv`.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {Test, console2} from 'forge-std/Test.sol';
import {IERC20} from '@openzeppelin/contracts/token/ERC20/IERC20.sol';
import {SafeERC20} from '@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol';

contract POC is Test {
    address constant USDT = 0xdAC17F958D2ee523a2206206994597C13D831ec7;
    address immutable owner = makeAddr("owner");
    address immutable spender = makeAddr("spender");

    function setUp() external {
       deal(USDT, owner, 1e6);
    }

    function testApproveRevert() external {
        vm.prank(owner);
        IERC20(USDT).approve(spender, 1e6);
    }

    function testApproveSuccess() external {
        vm.prank(owner);
        SafeERC20.forceApprove(IERC20(USDT), spender, 1e6);

        uint256 allowance = IERC20(USDT).allowance(owner, spender);
        assertEq(allowance, 1e6);
    }
}
```

## Code Snippet

https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/restaking/RioLRTIssuer.sol#L172

## Tool used

Manual Review

## Recommendation

Use `forceApprove` from OpenZeppelin's `SafeERC20` library.



## Discussion

**sherlock-admin4**

The protocol team fixed this issue in PR/commit https://github.com/rio-org/rio-sherlock-audit/pull/5.

# Issue M-12: Stakers can avoid validator penalties 

Source: https://github.com/sherlock-audit/2024-02-rio-network-core-protocol-judging/issues/190 

## Found by 
monrel, zzykxx
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



## Discussion

**nevillehuang**

Could be related to #52 and duplicates, both seems to involve front-running/sandwiching rebalance calls. Separated for now for further discussions


**solimander**

Valid, though need to take some time to consider whether this will be addressed. Could potentially frontrun slashing using any liquidity pool.

# Issue M-13: Heap is incorrectly stores the removed operator ID which can lead to division by zero in deposit/withdrawal flow 

Source: https://github.com/sherlock-audit/2024-02-rio-network-core-protocol-judging/issues/193 

## Found by 
almurhasan, itsabinashb, lemonmon, mstpr-brainbot, shaka, thec00n
## Summary
An operator's strategy can be reset by the owner calling `setOperatorStrategyCaps` to "0". This action sets the utilization to "0" and removes the operator from the heap. Consequently, this means that the operator has unwound all its strategy shares and can no longer receive any more deposits. However, due to how the heap is organized, if an operator who had funds before is reset to "0", the heap will not successfully remove the operator. As a result, when ordering the heap, a division by "0" will occur, causing the transaction to revert on deposits and withdrawals indefinitely.
## Vulnerability Detail
In order to break down the issue, let's divide the issue to 2 parts which their combination is the issue itself

**1- Heap is not removing the removed ID from the heaps storage when the operator is removed**

When the operator is removed, the operator will be removed from the heap as follows:
```solidity
function setOperatorStrategyCap(
        RioLRTOperatorRegistryStorageV1.StorageV1 storage s,
        uint8 operatorId,
        IRioLRTOperatorRegistry.StrategyShareCap memory newShareCap
    ) internal {
        .
        OperatorUtilizationHeap.Data memory utilizationHeap = s.getOperatorUtilizationHeapForStrategy(newShareCap.strategy);
        // If the current cap is greater than 0 and the new cap is 0, remove the operator from the strategy.
        if (currentShareDetails.cap > 0 && newShareCap.cap == 0) {
            // If the operator has allocations, queue them for exit.
            if (currentShareDetails.allocation > 0) {
                operatorDetails.queueOperatorStrategyExit(operatorId, newShareCap.strategy);
            }
            // Remove the operator from the utilization heap.
            -> utilizationHeap.removeByID(operatorId);
        }
        .

        // Persist the updated heap to the active operators tracking.
        -> utilizationHeap.store(s.activeOperatorsByStrategyShareUtilization[newShareCap.strategy]);
         .
    }
```

`removeByID` calls the internal `_remove` function which is **NOT** removes the last element! `self.count` is decreased however, the index is still the previous value of the `self.count`
```solidity
function _remove(Data memory self, uint8 i) internal pure {
        self.operators[i] = self.operators[self.count--];
    }
```

**For example, if there are 3 operators as follows:**
operatorId: 1, utilization: 50%
operatorId: 2, utilization: 60%
operatorId: 3, utilization: 70%
then, the `heap.count` would be 3
and the order would be: 1, 2, 3 in the heap
heap.operators[1] = operatorId 1
heap.operators[2] = operatorId 2
heap.operators[3] = operatorId 3

**if we remove the operator Id 2:**
`heap.count` = 2
order: 1,3
heap.operators[1] = operatorId 1
heap.operators[2] = operatorId 2
**heap.operators[3] = operatorId 0**  THIS SHOULD BE "0" since its removed but it is "3" in the current implementation!

As shown here, the operators[3] should be "0" since there isn't any operator3 in the heap anymore but the heap keeps the value and not resets it. 

**Here a test shows the above issue:**
```solidity
// forge test --match-contract OperatorUtilizationHeapTest --match-test test_removingDoesNotUpdatesStoredHeap -vv
    function test_removingDoesNotUpdatesStoredHeap() public {
        OperatorUtilizationHeap.Data memory heap = OperatorUtilizationHeap.initialize(5);

        heap.insert(OperatorUtilizationHeap.Operator({id: 1, utilization: 50}));
        heap.store(heapStore);

        heap.insert(OperatorUtilizationHeap.Operator({id: 2, utilization: 60}));
        heap.store(heapStore);

        heap.insert(OperatorUtilizationHeap.Operator({id: 3, utilization: 70}));
        heap.store(heapStore);

        console.log("Heaps count", heap.count);
        console.log("1st", heap.operators[1].id);
        console.log("2nd", heap.operators[2].id);
        console.log("3rd", heap.operators[3].id);

        // remove 2
        heap.removeByID(3);
        heap.store(heapStore);

        console.log("Heaps count", heap.count);
        console.log("1st", heap.operators[1].id);
        console.log("2nd", heap.operators[2].id);
        console.log("3rd", heap.operators[3].id);
    }
```
**Logs:**
<img width="563" alt="image" src="https://github.com/sherlock-audit/2024-02-rio-vesting-core-protocol-mstpr/assets/120012681/72ce2e8c-dd74-4e77-9bd7-f1096923165e">


**2- When the operator cap is reseted the allocations/deallocations will not work due to above heap issue because of division by zero**

Now, take the above example, we removed the operatorId 3 from the heap by setting its cap to "0". Now, there are only operators 1 and 2 active for that specific strategy.
When there are idle funds in the deposit pool before the rebalance call, the excess funds that are not requested as withdrawals will be pushed to EigenLayer as follows:
```solidity
function rebalance(address asset) external checkRebalanceDelayMet(asset) {
       .
       .
        -> (uint256 sharesReceived, bool isDepositCapped) = depositPool().depositBalanceIntoEigenLayer(asset);
        .
    }
```
```solidity
 function depositBalanceIntoEigenLayer(address asset) external onlyCoordinator returns (uint256, bool) {
        uint256 amountToDeposit = asset.getSelfBalance();
        if (amountToDeposit == 0) return (0, false);
        .
        .
        -> return (OperatorOperations.depositTokenToOperators(operatorRegistry(), asset, strategy, sharesToAllocate), isDepositCapped);
    }
```

```solidity
function depositTokenToOperators(
        IRioLRTOperatorRegistry operatorRegistry,
        address token,
        address strategy,
        uint256 sharesToAllocate
    ) internal returns (uint256 sharesReceived) {
       -> (uint256 sharesAllocated, IRioLRTOperatorRegistry.OperatorStrategyAllocation[] memory  allocations) = operatorRegistry.allocateStrategyShares(
            strategy, sharesToAllocate
        );
        .
        .
    }
```
```solidity
function allocateStrategyShares(address strategy, uint256 sharesToAllocate) external onlyDepositPool returns (uint256 sharesAllocated, OperatorStrategyAllocation[] memory allocations) {
        -> OperatorUtilizationHeap.Data memory heap = s.getOperatorUtilizationHeapForStrategy(strategy);
       .
       .
       .
       .
    }
```

```solidity
function getOperatorUtilizationHeapForStrategy(RioLRTOperatorRegistryStorageV1.StorageV1 storage s, address strategy) internal view returns (OperatorUtilizationHeap.Data memory heap) {
        uint8 numActiveOperators = s.activeOperatorCount;
        if (numActiveOperators == 0) return OperatorUtilizationHeap.Data(new OperatorUtilizationHeap.Operator[](0), 0);
        
        heap = OperatorUtilizationHeap.initialize(MAX_ACTIVE_OPERATOR_COUNT);
        LibMap.Uint8Map storage operators = s.activeOperatorsByStrategyShareUtilization[strategy];

        IRioLRTOperatorRegistry.OperatorShareDetails memory operatorShares;
        unchecked {
            uint8 i;
            for (i = 0; i < numActiveOperators; ++i) {
                uint8 operatorId = operators.get(i);

                // Non-existent operator ID. We've reached the end of the heap.
                if (operatorId == 0) break;

                operatorShares = s.operatorDetails[operatorId].shareDetails[strategy];
                heap.operators[i + 1] = OperatorUtilizationHeap.Operator({
                    id: operatorId,
                    -> utilization: operatorShares.allocation.divWad(operatorShares.cap)
                });
            }
            heap.count = i;
        }
    }
```
As we can see in one above code snippet, the `numActiveOperators` is 3. Since the stored heaps last element is not set to "0" it will point to operatorId 3 which has a cap of "0" after the removal. This will make the
```solidity
utilization: operatorShares.allocation.divWad(operatorShares.cap)
```
part of the code to perform a division by zero and the function will revert. 

**Coded PoC:**
```solidity
// forge test --match-contract RioLRTOperatorRegistryTest --match-test test_Capped0ValidatorBricksFlow -vv
    function test_Capped0ValidatorBricksFlow() public {
        // Add 3 operators
        addOperatorDelegators(reLST.operatorRegistry, address(reLST.rewardDistributor), 3);

        // The caps for each operator is 1000e18, we will delete the id 2 so we need funds there
        // any number that is more than 1000 should be ok for that experiement 
        uint256 AMOUNT = 1002e18;

        // Allocate to cbETH strategy.
        cbETH.approve(address(reLST.coordinator), type(uint256).max);
        uint256 lrtAmount = reLST.coordinator.deposit(CBETH_ADDRESS, AMOUNT);

        // Push funds into EigenLayer.
        vm.prank(EOA, EOA);
        reLST.coordinator.rebalance(CBETH_ADDRESS);

        // Build the empty caps
        IRioLRTOperatorRegistry.StrategyShareCap[] memory zeroStrategyShareCaps =
            new IRioLRTOperatorRegistry.StrategyShareCap[](1);
        zeroStrategyShareCaps[0] = IRioLRTOperatorRegistry.StrategyShareCap({strategy: CBETH_STRATEGY, cap: 0});

        // Set the caps of CBETH_STRATEGY for operator 2 as "0"
        reLST.operatorRegistry.setOperatorStrategyShareCaps(2, zeroStrategyShareCaps);

        // Try an another deposit, we expect revert when we do the rebalance
        reLST.coordinator.deposit(CBETH_ADDRESS, 10e18);

        // Push funds into EigenLayer. Expect revert, due to division by "0"
        skip(reETH.coordinator.rebalanceDelay());
        vm.startPrank(EOA, EOA);
        vm.expectRevert(bytes4(keccak256("DivWadFailed()")));
        reLST.coordinator.rebalance(CBETH_ADDRESS);
        vm.stopPrank();
    }
```
## Impact
Core logic broken, withdrawal/deposits can not be performed. 
## Code Snippet
https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/utils/OperatorRegistryV1Admin.sol#L231C5-L270C6

https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/utils/OperatorUtilizationHeap.sol#L94-L110

https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTCoordinator.sol#L121-L151

https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTDepositPool.sol#L47-L67

https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/utils/OperatorOperations.sol#L51-L68

https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTOperatorRegistry.sol#L342-L392

https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/utils/OperatorRegistryV1Admin.sol#L327-L351
## Tool used

Manual Review

## Recommendation
When removing from the heap also remove the last element from the heap.

**I am not sure of this, but this might work**
```solidity
function _remove(Data memory self, uint8 i) internal pure {
        self.operators[i] = self.operators[--self.count];
    }
```



## Discussion

**sherlock-admin4**

The protocol team fixed this issue in PR/commit https://github.com/rio-org/rio-sherlock-audit/pull/3.

**nevillehuang**

Severity could be higher, given a use of the function correctly results in blocking of withdrawals. Leaving medium for now on grounds of admin error

# Issue M-14: Lack of slippage parameters can affect the LRT / share amounts during deposits / withdrawals 

Source: https://github.com/sherlock-audit/2024-02-rio-network-core-protocol-judging/issues/214 

The protocol has acknowledged this issue.

## Found by 
Bauer, HSP, PNS, abiih, almurhasan, avoloder, cats, iamandreiski, merlin, nisedo, sakshamguruji, sunill\_eth, thank\_you, zraxx
## Summary

During both deposits and withdrawals, the amount that the user receives in LRT tokens (during deposits) or amount of shares (during withdrawals) Is dependent on mainly the correlation between the supply of the given asset, the TVL (total value locked) and the price fetched from an oracle. 

Since the total value locked is dependent on the amount of shares recorded in the accounting system for the underlying asset in-question / all assets (updated during rebalances) + the balance of the assets in the contract (updated whenever the deposit is sent) this means that the value a user receives in return when depositing is dependent on the of the amount of shares + the current balance recorded in the protocol. 

During stepwise jumps in rewards accumulation and/or large deposits/withdrawals to/from the system, the TVL can drastically change, affecting the price ratio between the underlying assets and LRT. Users can get receive less LRT/shares than expected their deposit/withdrawal transaction was frontrun by a very large transaction, the protocol was rebalanced, etc.

## Vulnerability Detail

When deposits are made, the calculations for the amount of LRT tokens the user will get in return versus the number of shares is calculated by using the following formulas. Let's take a look at the deposit flow:

**Deposits:**

Once `amountOut` is calculated, this will determine the amount of LRT tokens that the user will receive in exchange for their deposit in the underlying token (for e.g. reETH, cbETH, etc.) 

`        amountOut = convertFromAssetToRestakingTokens(asset, amountIn);`

```solidity
  function convertFromAssetToRestakingTokens(address asset, uint256 amount) public view returns (uint256) {
        uint256 value = assetRegistry().convertToUnitOfAccountFromAsset(asset, amount);
        return convertFromUnitOfAccountToRestakingTokens(value);
    }
```
From the above the `value` parameter will be calculated by fetching the price from the price oracle: 

```solidity
function convertToUnitOfAccountFromAsset(address asset, uint256 amount) public view returns (uint256) {
        if (asset == ETH_ADDRESS) {
            return amount;
        }
        address priceFeed = assetInfo[asset].priceFeed;
        uint256 price = getPrice(priceFeed);

        return _normalizeDecimals(price * amount / priceScale, assetInfo[asset].decimals, priceFeedDecimals);
    }
```
After `value` is returned using the above calculations, then we will call the `convertFromUnitOfAccountToRestakingTokens()` with the `value` parameter as a function argument. This function will output the amount of LRT tokens that the user should receive based on the calculations below:

```solidity
function convertFromUnitOfAccountToRestakingTokens(uint256 value) public view returns (uint256) {
        uint256 tvl = getTVL();
        uint256 supply = token.totalSupply();

        if (supply == 0) {
            return value;
        }
        return value * supply / tvl;
    }
```
As we can see, the above function utilizes the TVL (Total Value Locked) in the protocol (of all underlying assets) to come up with the price. The TVL is greatly dependent on the amount of shares currently accounted for in the system: 

```solidity
function getTVLForAsset(address asset) public view returns (uint256) {
        uint256 balance = getTotalBalanceForAsset(asset);
        if (asset == ETH_ADDRESS) {
            return balance;
        }
        return convertToUnitOfAccountFromAsset(asset, balance);
```

The way that `balance` is calculated, since it's crucial for the TVL which is based on balance * oraclePriceForAsset; it takes into consideration all of the asset shares held in Rio: `assetInfo[asset].shares` + the `balanceOf(asset)`:

```solidity
  uint256 sharesHeld = getAssetSharesHeld(asset);
        uint256 tokensInRio = IERC20(asset).balanceOf(depositPool_);
        uint256 tokensInEigenLayer = convertFromSharesToAsset(getAssetStrategy(asset), sharesHeld);

        return tokensInRio + tokensInEigenLayer;
```

**PoC**
- For simpler calculations, let's say that Alice wants to deposit ETH through the `depositETH()` function:

```solidity
        // Convert deposited ETH to restaking tokens and mint to the caller.
        amountOut = convertFromUnitOfAccountToRestakingTokens(msg.value);

        // Forward ETH to the deposit pool.
        address(depositPool()).transferETH(msg.value);
```
- Alice wants to deposit 1 ETH (1e18), the current protocol TVL is 35e18, and the total supply of ETH is 12e25.
- To calculate the `amountOut`:
```solidity
 function convertFromUnitOfAccountToRestakingTokens(uint256 value) public view returns (uint256) {
        uint256 tvl = getTVL();
        uint256 supply = token.totalSupply();

        if (supply == 0) {
            return value;
        }
        return value * supply / tvl;
    }
```
- 1e18 * 12e25 / 1500e18.
- The amount of shares she will receive is 1.2e24
- If she was frontrun by a large transaction of let's say 200 ETH
- The amount would be: 1e18 * 12e25 / 1700e18 = 7e22.

## Impact

LRT tokens received in exchange for the underlying assets can vary and lead to unwanted outcomes due to the price dependency on the TVL as well as the amount of tokens received by the user is determined by an interaction with an oracle, meaning that the amount received in return may vary indefinitely while the request is waiting to be executed.
This is due to a lack of slippage control on any of the deposit / withdrawal functions. 

## Code Snippet
https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/restaking/RioLRTCoordinator.sol#L79

https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/restaking/RioLRTCoordinator.sol#L162-L169

https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/restaking/RioLRTCoordinator.sol#L219

## Tool used

Manual Review

## Recommendation

Include minimumOut parameters and maybe a deadline as well to enforce slippage control to the deposit/withdraw transactions in order to prevent unwanted outcomes.



## Discussion

**nevillehuang**

Borderline medium/low leaving open for discussion.

**solimander**

Consider low severity - oracle updates of underlying assets and reward distributions are unlikely to cause a meaningful change to the output amount.

**nevillehuang**

I believe this should have been a known consideration stated in the contest details, so leaving as medium severity

# Issue M-15: All operators can have ETH deposits regardless of the cap setted for them leading to miscalculated TVL 

Source: https://github.com/sherlock-audit/2024-02-rio-network-core-protocol-judging/issues/235 

## Found by 
hash, klaus, mstpr-brainbot, neumo, zzykxx
## Summary
Some operators might not be eligible for using some strategies in the LRT's underlying tokens. However, in default every operator can have ETH deposits which would impact the TVL/Exchange rate of the LRT regardless of they have a cap or not. 
## Vulnerability Detail
First, let's examine how an operator can have ETH deposit

An operator can have ETH deposits by simply staking in beacon chain, to do so they are not mandatory to call EigenPods "stake" function. They can do it separately without calling the EigenPods [stake](https://github.com/Layr-Labs/eigenlayer-contracts/blob/6de01c6c16d6df44af15f0b06809dc160eac0ebf/src/contracts/pods/EigenPod.sol#L403-L412) function. 

Also, every operator delegator contract can call [`verifyWithdrawalCredentials`](https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTOperatorDelegator.sol#L135-L145) to increase EigenPod shares and decrease the queued ETH regardless of they are active operator or they have a cap determined for BEACON_CHAIN_STRATEGY. 

Now, let's look at how the TVL of ETH (BEACON_CHAIN_STRATEGY) is calculated in the AssetRegistry:
```solidity
function getTVLForAsset(address asset) public view returns (uint256) {
        uint256 balance = getTotalBalanceForAsset(asset);
        if (asset == ETH_ADDRESS) {
            return balance;
        }
        return convertToUnitOfAccountFromAsset(asset, balance);
    }

    function getTotalBalanceForAsset(address asset) public view returns (uint256) {
        if (!isSupportedAsset(asset)) revert ASSET_NOT_SUPPORTED(asset);

        address depositPool_ = address(depositPool());
        if (asset == ETH_ADDRESS) {
            return depositPool_.balance + getETHBalanceInEigenLayer();
        }

        uint256 sharesHeld = getAssetSharesHeld(asset);
        uint256 tokensInRio = IERC20(asset).balanceOf(depositPool_);
        uint256 tokensInEigenLayer = convertFromSharesToAsset(getAssetStrategy(asset), sharesHeld);

        return tokensInRio + tokensInEigenLayer;
    }

    function getETHBalanceInEigenLayer() public view returns (uint256 balance) {
        balance = ethBalanceInUnverifiedValidators;

        IRioLRTOperatorRegistry operatorRegistry_ = operatorRegistry();
        -> uint8 endAtID = operatorRegistry_.operatorCount() + 1; // Operator IDs start at 1.
        -> for (uint8 id = 1; id < endAtID; ++id) {
            -> balance += operatorDelegator(operatorRegistry_, id).getETHUnderManagement();
        }
    }
```

As we can see above, regardless of the operators cap the entire active validator counts are looped. 

```solidity
function getEigenPodShares() public view returns (int256) {
        return eigenPodManager.podOwnerShares(address(this));
    }

    function getETHQueuedForWithdrawal() public view returns (uint256) {
        uint256 ethQueuedSlotData;
        assembly {
            ethQueuedSlotData := sload(ethQueuedForUserSettlementGwei.slot)
        }

        uint64 userSettlementGwei = uint64(ethQueuedSlotData);
        uint64 operatorExitAndScrapeGwei = uint64(ethQueuedSlotData >> 64);

        return (userSettlementGwei + operatorExitAndScrapeGwei).toWei();
    }

    function getETHUnderManagement() external view returns (uint256) {
        int256 aum = getEigenPodShares() + int256(getETHQueuedForWithdrawal());
        if (aum < 0) return 0;

        return uint256(aum);
    }
```

Since the operator has eigen pod shares, the TVL will account it aswell. However, since the operator is not actively participating on ether deposits (not in the heap order) the withdrawals or deposits to this specific operator is impossible. Hence, the TVL is accounting an operators eigen pod share which the contract assumes that it is not in the heap. 

**Textual PoC:**
Assume there are 5 operators whereas only 4 of these operators are actively participating in BEACON_CHAIN_STRATEGY which means that 1 operator has no validator caps set hence, it is not in the heap order.
However, this operator can still have ether deposits and can verify them. Since the TVL accounting **loops over all the operators but not the operators that are actively participating in beacon chain strategy**, the TVL calculated will be wrong. 
## Impact
Miscalculation of total ether holdings of an LRT. Withdrawals can fail because the calculated ether is not existed in the heap but the TVL says there are ether to withdraw from the LRT.
## Code Snippet
https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTAssetRegistry.sol#L79-L114

https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTOperatorDelegator.sol#L101-L126
## Tool used

Manual Review

## Recommendation
put a check on `verifyWithdrawalCredentials` that is not possible to call the function if the operator is not actively participating in the BEACON_CHAIN_STRATEGY. 



## Discussion

**solimander**

This is a necessary feature, and should be a short-lived quirk. If an operator is deactivated prior to all validator withdrawal credentials being proven, they will need to prove the credentials and withdraw after deactivation, which would then be scraped back into the deposit pool.

**nevillehuang**

I believe this should have been a known consideration stated in the contest details, so leaving as medium severity.

# Issue M-16: Users can receive less tokens than expected due to precision loss 

Source: https://github.com/sherlock-audit/2024-02-rio-network-core-protocol-judging/issues/264 

## Found by 
Bauer, dany.armstrong90, itsabinashb, sobieski, thank\_you, thec00n
## Summary

When user makes a deposit into the RIO LRT Coordinator, the amount of due LST is calculated with a precision loss bug. As a result, the user can receive much less LST than expected.

## Vulnerability Detail

Users can deposit asset to Rio via the `RioLRTCoordinator::deposit()` method. Inside this method, the due `amountOut` of LST is calculated like this:

```javascript
amountOut = convertFromAssetToRestakingTokens(asset, amountIn);
```

The method `RioLRTCoordinator::convertFromAssetToRestakingTokens()` does the following calculation:

```javascript
function convertFromAssetToRestakingTokens(address asset, uint256 amount) public view returns (uint256) {
        uint256 value = assetRegistry().convertToUnitOfAccountFromAsset(asset, amount);
        return convertFromUnitOfAccountToRestakingTokens(value);
}
```

In order to calculate the due amount of LST, the value of asset deposited by the user gets converted to ETH. Subsequently, the value in ETH gets converted to the value in LST. The first calculation of value in ETH is executed in the `RioLRTAssetRegistry::convertToUnitOfAccountFromAsset()` method:

```javascript
function convertToUnitOfAccountFromAsset(address asset, uint256 amount) public view returns (uint256) {
        if (asset == ETH_ADDRESS) {
            return amount;
        }
        address priceFeed = assetInfo[asset].priceFeed;
        uint256 price = getPrice(priceFeed);

        return _normalizeDecimals(price * amount / priceScale, assetInfo[asset].decimals, priceFeedDecimals);
}
```

The math is as follows:

**valueInEth = \_normalizeDecimals(price \* amount / priceScale, tokenDecimals, priceFeedDecimals)**

When we investigate the `RioLRTAssetRegistry::_normalizeDecimals()` method, we can see that it multiplies or divides the argument by the difference between decimals of asset and its price feed:

```javascript
function _normalizeDecimals(uint256 amount, uint8 fromDecimals, uint8 toDecimals) internal pure returns (uint256) {
        // No adjustment needed if decimals are the same.
        if (fromDecimals == toDecimals) {
            return amount;
        }
        // Scale down to match the target decimal precision.
        if (fromDecimals > toDecimals) {
            return amount / 10 ** (fromDecimals - toDecimals);
        }
        // Scale up to match the target decimal precision.
        return amount * 10 ** (toDecimals - fromDecimals);
}
```

Let's consider a scenario where the decimals of token asset (`fromDecimals`) are smaller than the decimals of price feed (`toDecimals`). As example of such a scenario will be `USDT` asset, which has 6 decimals, while its price feed has 18 decimals.

The final formula for the ETH value will be then as follows:

**valueInEth = (price \* amount / priceScale) \* 10 \*\* (toDecimals - fromDecimals)**

Applying the `USDT` scenario decimals gives us:

**valueInEth = (price \* amount / 10e18) \* 10e12**

We can see a division happening before multiplication. As Solidity rounds down integer divisions, it is strongly advised to perform multiplications before divisions in order to avoid precision losses. This advice is not followed here and the calculation leads to loss of precision.

The vulnerable method `RioLRTAssetRegistry::_normalizeDecimals()` is also utilized in calculating the amounts for withdrawal and calculating the TVLs. As such, the precision loss issue scope is broad as it affects multiple scenarios of interaction within the Rio protocol.

## Impact

The amount of LST minted for the user can be much less than expected if the deposited asset decimals are lower than price feed decimals. This scenario is likely to happen, as the documentation states:

> We plan to support tokens with no less than 6 decimals and no more than 18 decimals

The precision loss may also impact the amounts withdrawn from the Protocol.

## Proof of concept

Run the following test inside a Foundry test suite to demonstrate the precision loss:

```javascript
function test_precisionLoss(uint256 amount) public {
        vm.assume(amount > 1e6);
        vm.assume(amount < 1000e6);       

        uint256 price = 294104713183814; //The USDT/ETH hardcoded price
        uint256 tokenDecimals = 6;
        uint256 priceFeedDecimals = 18;
        uint256 priceScale = uint64(10) ** priceFeedDecimals; //10e18
        uint256 decimalsNormalizer = uint64(10) ** (priceFeedDecimals - tokenDecimals); //10e12

        uint256 priceCalculatedAsForNow = ((price * amount / priceScale) * decimalsNormalizer);
        uint256 priceCalculatedCorrectly = ((price * amount * decimalsNormalizer) / priceScale);
        
        assertEq(priceCalculatedAsForNow, priceCalculatedCorrectly);
}
```

Example of precision loss:

```javascript
Error: a == b not satisfied [uint]
        Left: 294000000000000
       	Right: 294105007288527
```

## Code Snippet

https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/restaking/RioLRTAssetRegistry.sol#L195

## Tool used

Manual Review

## Recommendation

Always execute the division after the multiplications to avoid precision loss.



## Discussion

**nevillehuang**

Borderline Medium/Low, leaving open for discussion, what is the maximum possible loss here?

**solimander**

In practice, precision losses will be dust.

# Issue M-17: Slashing penalty is unfairly paid by a subset of users if a deficit is accumulated. 

Source: https://github.com/sherlock-audit/2024-02-rio-network-core-protocol-judging/issues/363 

## Found by 
monrel
## Summary

If a deficit is accumulated in the EigenPodManager due to slashing when ETH is being withdrawn the slashing payment will be taken from the first cohort to complete a withdrawal.

## Vulnerability Detail

A deficit can happen in `podOwnerShares[podOwner]` in the EigenPodManager in the EigenLayer protocol. This can happen if validators are slashed when ETH is queued for withdrawal.

The issue is that this deficit will be paid for by the next cohort to complete a withdrawal by calling `settleEpochFromEigenLayer()`.

In the following code we can see how `epochWithdrawals.assetsReceived` is calculated based on the amount received from the `delegationManager.completeQueuedWithdrawal` call

https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTWithdrawalQueue.sol#L242-L268

```solidity
        uint256 balanceBefore = asset.getSelfBalance();

        address[] memory assets = asset.toArray();
        bytes32[] memory roots = new bytes32[](queuedWithdrawalCount);

        IDelegationManager.Withdrawal memory queuedWithdrawal;
        for (uint256 i; i < queuedWithdrawalCount; ++i) {
            queuedWithdrawal = queuedWithdrawals[i];

            roots[i] = _computeWithdrawalRoot(queuedWithdrawal);
            delegationManager.completeQueuedWithdrawal(queuedWithdrawal, assets, middlewareTimesIndexes[i], true);

            // Decrease the amount of ETH queued for withdrawal. We do not need to validate the staker as
            // the aggregate root will be validated below.
            if (asset == ETH_ADDRESS) {
                IRioLRTOperatorDelegator(queuedWithdrawal.staker).decreaseETHQueuedForUserSettlement(
                    queuedWithdrawal.shares[0]
                );
            }
        }
        if (epochWithdrawals.aggregateRoot != keccak256(abi.encode(roots))) {
            revert INVALID_AGGREGATE_WITHDRAWAL_ROOT();
        }
        epochWithdrawals.shareValueOfAssetsReceived = SafeCast.toUint120(epochWithdrawals.sharesOwed);

        uint256 assetsReceived = asset.getSelfBalance() - balanceBefore;
        epochWithdrawals.assetsReceived += SafeCast.toUint120(assetsReceived);
```

the amount received could be 0 if the deficit is larger than the amount queued for this cohort. See following code in `withdrawSharesAsTokens()` EigenPodManager

https://github.com/Layr-Labs/eigenlayer-contracts/blob/e12b03f20f7dceded8de9c6901ab05cfe61a2113/src/contracts/pods/EigenPodManager.sol#L216C1-L220C14

```solidity
            } else {
                podOwnerShares[podOwner] += int256(shares);
                emit PodSharesUpdated(podOwner, int256(shares));
                return;
            }
```

These users will pay for all slashing penalties instead of it being spread out among all LRT holders.

## Impact

If a deficit is accumulated the first cohort to settle will pay for the entire amount. If they can not cover it fully, they will receive 0 and the following cohort will pay for the rest.

## Code Snippet

https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTWithdrawalQueue.sol#L242-L268

## Tool used

Manual Review
## Recommendation

A potential solution to deal with this is to check if a deficit exists in `settleEpochFromEigenLayer()`. If it exists functionality has to be added that spreads the cost of the penalty fairly among all LRT holders.



## Discussion

**nevillehuang**

request poc

**sherlock-admin3**

PoC requested from @0xmonrel

Requests remaining: **16**

**0xmonrel**


For this POC to run we need to first fix the epoch increment issue. Done by adding `currentEpochsByAsset[asset] += 1;` to queueCurrentEpcohSettlement().

### POC

This shows that users in the first withdrawal pay for 100% of the penalty if we have a deficit due to slashing

Course of events
1. Deposit such that we have 2 validators
2. Request withdrawal 8 ETH and rebalance for epoch 0
3. Request withdrawal 31.99 ETH and rebalance for epoch 1
4. Slashing during withdrawal period such that we have a -8 ETH deficit in the EigenpodManager
5. VerifyAndProcess both withdrawals
6. Settle and claim epoch 0, we get 0 ETH since penalty is paid for 100% by these users.
7. Settle and claim epoch 1, we get 31.99 ETH since 0% of penalty is paid for. 
8. Users in epoch 1 has stolen 4 ETH from users in epoch 0.

Create a new file `RioLRTDeficit.t.sol` in the `test` folder and paste the code below. Run with `forge test --match-test test_deficitPenaltyTrue -vvv`

```solidity
// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.23;

import {BEACON_CHAIN_STRATEGY, ETH_ADDRESS, ETH_DEPOSIT_SIZE, GWEI_TO_WEI} from 'contracts/utils/Constants.sol';
import {IDelegationManager} from 'contracts/interfaces/eigenlayer/IDelegationManager.sol';
import {IRioLRTWithdrawalQueue} from 'contracts/interfaces/IRioLRTWithdrawalQueue.sol';
import {RioDeployer} from 'test/utils/RioDeployer.sol';
import {Asset} from 'contracts/utils/Asset.sol';
import {Array} from 'contracts/utils/Array.sol';

import {IRioLRTOperatorRegistry} from 'contracts/interfaces/IRioLRTOperatorRegistry.sol';
import {RioLRTOperatorDelegator} from 'contracts/restaking/RioLRTOperatorDelegator.sol';
import {CredentialsProofs, BeaconWithdrawal} from 'test/utils/beacon-chain/MockBeaconChain.sol';
import "forge-std/console2.sol";
import {IEigenPodManager} from 'contracts/interfaces/eigenlayer/IEigenPodManager.sol';
import {stdStorage, StdStorage} from "forge-std/Test.sol";

contract RioLRTDeficit is RioDeployer {
    using stdStorage for StdStorage; 
    using Asset for *;
    using Array for *;

    TestLRTDeployment public reETH;
    TestLRTDeployment public reLST;

    IRioLRTOperatorRegistry.StrategyShareCap[] public emptyStrategyShareCaps; 
    function setUp() public {
        deployRio(); 

        (reETH,) = issueRestakedETH(); 
        (reLST,) = issueRestakedLST();
    }


    function test_deficitPenaltyTrue() public{
        uint8[] memory operatorIds = addOperatorDelegators( //add 2 validators to 1 operator
        reETH.operatorRegistry,
        address(reETH.rewardDistributor),
        1,
        emptyStrategyShareCaps,
        2
        );
        
        uint256 depositAmount = 2*ETH_DEPOSIT_SIZE - address(reETH.depositPool).balance;  
        reETH.coordinator.depositETH{value: depositAmount}(); 


        vm.prank(EOA, EOA);
        reETH.coordinator.rebalance(ETH_ADDRESS); // Rebalance to stake 2 validators
        uint40[] memory validatorIndices = verifyCredentialsForValidators(reETH.operatorRegistry, 1, 2);
        
        address delegator = reETH.operatorRegistry.getOperatorDetails(operatorIds[0]).delegator;
        
        int256 shares = RioLRTOperatorDelegator(payable(delegator)).getEigenPodShares();         

        console2.log("Total shares after deposit:",shares);
        require(shares == 64 ether);

       
       //----- First withdrawal

        uint256 withdrawalAmount = 8 ether;
        reETH.coordinator.requestWithdrawal(ETH_ADDRESS, withdrawalAmount);
        
        uint256 firstEpoch = reETH.withdrawalQueue.getCurrentEpoch(ETH_ADDRESS);
        
        skip(reETH.coordinator.rebalanceDelay());

        vm.prank(EOA, EOA);
        reETH.coordinator.rebalance(ETH_ADDRESS);

        //----- Second Withdrawal

        uint256 withdrawalAmount2 = 31.99 ether;
        reETH.coordinator.requestWithdrawal(ETH_ADDRESS, withdrawalAmount2);

        uint256 secondEpoch = reETH.withdrawalQueue.getCurrentEpoch(ETH_ADDRESS);

        skip(reETH.coordinator.rebalanceDelay());

        vm.prank(EOA, EOA);
        reETH.coordinator.rebalance(ETH_ADDRESS);
        
        // ------ SIMULATE SLASHING 
        // EigenLayer accounts for slashing during withdrawl period by decreasing shares. 
        // if shares < 0, these shares will be adjusted for in the next withdrawal.

        /** We simulate slashing by directly setting the podownerShars[delegator] = slashedAmount
            this is equivalent to calling recordBeaconChainETHBalanceUpdate to decrease the balance
            due to slashing.
         */

        IEigenPodManager manager = IEigenPodManager(EIGEN_POD_MANAGER_ADDRESS);

        stdstore.target(EIGEN_POD_MANAGER_ADDRESS).sig("podOwnerShares(address)").with_key(delegator).checked_write_int(int256(-8 ether));

        int256 loadInt = stdstore.target(EIGEN_POD_MANAGER_ADDRESS).sig("podOwnerShares(address)").with_key(delegator).read_int();
        console2.log("Slashing 8 Ether during withdrawal process, deficit in shares:", loadInt);
        
        // verify both

        verifyAndProcessWithdrawalsForValidatorIndexes(delegator, validatorIndices);

        // First withdrawal will pay for entire slashing amount

    {
        IDelegationManager.Withdrawal[] memory withdrawals = new IDelegationManager.Withdrawal[](1);
        withdrawals[0] = IDelegationManager.Withdrawal({
            staker: delegator,
            delegatedTo: address(1),
            withdrawer: address(reETH.withdrawalQueue),
            nonce: 0,
            startBlock: 1,
            strategies: BEACON_CHAIN_STRATEGY.toArray(),
            shares: withdrawalAmount.toArray()
        });
        reETH.withdrawalQueue.settleEpochFromEigenLayer(ETH_ADDRESS, 0, withdrawals, new uint256[](1));


        uint256 amountOut = reETH.withdrawalQueue.claimWithdrawalsForEpoch(
            IRioLRTWithdrawalQueue.ClaimRequest({asset: ETH_ADDRESS, epoch: 0})
        );
        
        console2.log("First Withdrawal:", amountOut); // Users in this cohort pay for 100% of slashing
    }


        IDelegationManager.Withdrawal[] memory withdrawals2 = new IDelegationManager.Withdrawal[](1);
        withdrawals2[0] = IDelegationManager.Withdrawal({
            staker: delegator,
            delegatedTo: address(1),
            withdrawer: address(reETH.withdrawalQueue),
            nonce: 1,
            startBlock: 1,
            strategies: BEACON_CHAIN_STRATEGY.toArray(),
            shares: withdrawalAmount2.toArray()
        });
        reETH.withdrawalQueue.settleEpochFromEigenLayer(ETH_ADDRESS, 1, withdrawals2, new uint256[](1));

        uint256 amountOut2 = reETH.withdrawalQueue.claimWithdrawalsForEpoch(
            IRioLRTWithdrawalQueue.ClaimRequest({asset: ETH_ADDRESS, epoch: 1})
        );
        
        console2.log("Second Withdrawal:", amountOut2); // Users in this cohort pay 0% of slashing
        console2.log("Users in first withdrawal paid for 100% of penalty");
        
    }    
    receive() external payable {}
}

```

### Results

```javascript
Logs:
  Total shares after deposit: 64000000000000000000
  Slashing 8 Ether during withdrawal process, deficit in shares: -8000000000000000000
  First Withdrawal: 0
  Second Withdrawal: 31990000000000000000
  Users in first withdrawal paid for 100% of penalty
```



**nevillehuang**

@solimander Might want to consider the above PoC

**solimander**

Reviewing

# Issue M-18: The current idea of ​​creating reETH and accepting several different assets in it exposes RIO users to losses 

Source: https://github.com/sherlock-audit/2024-02-rio-network-core-protocol-judging/issues/386 

The protocol has acknowledged this issue.

## Found by 
ComposableSecurity, PNS, Thanos, fugazzi, zzykxx

## Summary
After the release of LRT, which will include the ability to deposit native eth and wrapped staking tokens like cbETH or wstETH, Rio users will be exposed to additional economic risks that may lead to loss of capital. In case of a predictable price drop (e.g. caused by a slashing event in an external liquid staking provider), external users can deposit their funds into Rio before the price drop. They will receive the LRT (corresponding to the value before the price drop, as priceFeed displays the changed price only when it actually happens) and withdraw them once the price drops, sharing their loss with Rio users.

## Vulnerability Detail
Rio creates a network for issuing Liquid Restaking Tokens (LRTs) that have an underlying asset mix. The idea is to have multiple LRTs like: reUSD, reETH, reXXX, where for reUSD underlying asset mix will include e.g. USDC, DAI, USDT and for reETH underlying asset mix will include native ETH and e.g. cbETH (as it is used in tests), or wstETH.

Users depositing their funds into Rio are encouraged by the rewards of staking and re-staking through EigenLayer, but they also bear the risk of penalties and slashing of their deposited funds. However, in case of reETH, the 3rd party users who are not associated in any way with Rio ecosystem can take advantage of such LRT and make Rio users bear their losses.

Keeping in mind these things:
- value of assets like wstETH, cbETH generally increase over time,
- there are price drops for assets like wstETH, cbETH, but most of the time these are temporary,
- things that can cause price drops for assets like wstETH, cbETH include: slashing, lower demand / lack of trust for particular asset, withdrawal caused by people who accumulated big rewards over time,
- lower demand / lack of trust is unpredictable, however, big withdrawals can be monitored and slashing is a process spread over time, so there is a time when you know the value of asset will drop,
- liquid staking providers like LIDO etc., protects themselves from "withdrawal before slashing" by making withdrawal process long enough so that slashing can affect the users who request to withdraw,
- user within Rio ecosystem can deposit asset1 to get LRT, and then request to withdraw asset2.

Consider the following scenario (**values used for ease of calculation and to illustrate the attack**, real values will be presented later in this description):

Rio issues LRT (reETH) that supports two assets (cbETH and native ETH).

1. 200 ETH is deposited inside RIO by users and 200 reETH were minted.

2. The attacker (cbETH staker) has 100 cbETH (price is e.g. 1 cbETH = 2 ETH, their cbETH is worth 200 ETH)

The attacker knows through monitoring slashing events and big withdrawalas that price will drop soon.

3. The attacker deposit their 100 cbETH to Rio to get 200 reETH (as current price is still 1 cbETH = 2 ETH)

Total value locked on Rio will increase from 200 ETH to 400 ETH (200 eth and 100 cbETH)

Price of cbETH now drops by 50% (so now 1 cbETH = 1 ETH)

Total value locked on Rio will decrease from 400 ETH to 300 ETH (as 200cbETH is now worth only 100 ETH).

4. The attacker decides to request withdraw all of their cbETH by burning only 150 reETH and they also request to withdraw 50 ETH by burning another 100 reETH.

5. Attacker gets 200 cbETH back (current price is 100 ETH) and additional 50 ETH.

6. Attacker buys additional cbETH for their additional 50 ETH, so know they have 250 cbETH (from another source)

Now price recover, so its again 1 cbETH = 2 ETH.

Attacker now have 250 cbETH worth 500 ETH, and Rio users have 150 ETH (lost 50 ETH, as attacker delegeted their risk to rio users).


However, the price will not drop by 50%. The real numbers could be up to 10%.

Looking at 2 examples of assets that are considered to be added to reETH (cbETH and wstETH) we can observe the following:

1. cbETH (https://coinmarketcap.com/currencies/coinbase-wrapped-staked-eth/)

* there are price drops
* based on data from last 365 days the biggest percentage drop in price occurred on March 11, 2023, with a drop of approximately 8.25% (https://coinmarketcap.com/currencies/lido-finance-wsteth/historical-data/) (https://coinmarketcap.com/currencies/coinbase-wrapped-staked-eth/historical-data/)

2. wstETH (https://coinmarketcap.com/currencies/lido-finance-wsteth/)

* there are price drops
* based on data from last 365 days the biggest percentage drop in price occurred also on March 11, 2023, with a drop of approximately 9.28% (https://coinmarketcap.com/currencies/lido-finance-wsteth/historical-data/)


## Impact
MEDIUM - as it require conditions that needs to be satisfied (observed in advance price drop) and funds which cannot be possed in flash-loan to increase the impact of the vulnerability.

## Code Snippet
https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTCoordinator.sol#L99
https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTCoordinator.sol#L101C22-L101C56

## Tool used

Manual Review

## Recommendation
The problem is not easy to fix and several security mechanisms can be used:
- users could be allowed to withdraw only the type of assets they deposit
- you can monitor price drop events and temporarily freeze deposits
- you can set a minimum period for the user between his deposit and withdrawal so that he cannot take advantage of price fluctuations
- single LRTs can be issued for assets that are subject to such events (price drops predicted some time in advance)



## Discussion

**nevillehuang**

Maintaining as valid medium, given I believe this should have been made known as accepted risks in the contest details

