Obedient Carbon Leopard

high

# Pending EigenLayer withdrawal can stuck

## Summary
When requested withdrawals do not cover the idle tokens in the deposit pool, EigenLayer shares are withdrawn, but this process has a delay. The epoch should not be settled until the claiming from EigenLayer occurs. However, if there are sufficient deposits to the pool in the meantime, the epoch can be settled. In this scenario, the previously requested withdrawal from that epoch would remain pending.
## Vulnerability Detail
When there are not enough tokens to satisfy the total withdrawals in the epoch, EigenLayer is called to queue the withdrawals. The function responsible for this is as follows:

[Link to the function](https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTWithdrawalQueue.sol#L177C5-L209C6)

As we can see, the epoch is not settled, meaning any further withdrawal requests or deposits will still belong to the same epoch.

There can be many issues arising from the same root cause, I will list some of them:

1- If there are deposits to the pool via the Coordinator (normal flow), then the epoch can be settled in the next rebalance. This would increase the epoch and start a new one, even though the previous epoch still has a pending withdrawal from EigenLayer, making it impossible to claim since it's settled with the new deposits.
2- Further withdrawal requests to the same epoch can decrease the shares received by the first withdrawers if the deposits to the pool do not fully cover the new withdrawals.
3- Further withdrawal requests to the same epoch may not go through because the current epoch already has an "aggregateRoot."
 
**Coded PoC:**
```solidity
    function test_EpochCanBeSettledWhile_OngoingEigenLayerWithdrawal() public {
        uint256 initialTotalSupply = reLST.token.totalSupply();

        uint8 operatorId = addOperatorDelegator(reLST.operatorRegistry, address(reLST.rewardDistributor));
        address operatorDelegator = reLST.operatorRegistry.getOperatorDetails(operatorId).delegator;

        uint256 amount = 18e18;
        uint256 expectedTokensOut = amount * 2; // Two deposits of `amount`.

        // Deposit cbETH, rebalance, and deposit again to create a balance in EigenLayer
        // and the deposit pool.
        cbETH.approve(address(reLST.coordinator), type(uint256).max);
        uint256 restakingTokensInEL = reLST.coordinator.deposit(CBETH_ADDRESS, amount);

        vm.prank(EOA, EOA);
        reLST.coordinator.rebalance(CBETH_ADDRESS);
        uint256 restakingTokensInDP = reLST.coordinator.deposit(CBETH_ADDRESS, amount);

        // Request a withdrawal for an amount greater than the deposit pool balance and rebalance.
        uint256 withdrawalLRTAmount = restakingTokensInDP + restakingTokensInEL;
        reLST.coordinator.requestWithdrawal(CBETH_ADDRESS, withdrawalLRTAmount);
        skip(reLST.coordinator.rebalanceDelay());

        vm.prank(EOA, EOA);
        reLST.coordinator.rebalance(CBETH_ADDRESS);

        // Validate that the deposit pool balance has been removed from the reLST total supply.
        assertApproxEqAbs(reLST.token.totalSupply(), restakingTokensInEL + initialTotalSupply, 100);
        
        // @review deposit 3 * amount from a different user which is bigger than whats requested in the prev epoch from EigenLayer
        uint256 newAmountAdded = reLST.coordinator.deposit(CBETH_ADDRESS, amount * 3);
        skip(reLST.coordinator.rebalanceDelay());

        uint256 withdrawalEpoch = reLST.withdrawalQueue.getCurrentEpoch(CBETH_ADDRESS);
        // @review rebalance, this shouldn't settle epoch since there is pending withdrawals but it will settle
        vm.prank(EOA, EOA);
        reLST.coordinator.rebalance(CBETH_ADDRESS);

        IRioLRTWithdrawalQueue.EpochWithdrawalSummary memory epochSummary =
            reLST.withdrawalQueue.getEpochWithdrawalSummary(CBETH_ADDRESS, withdrawalEpoch);
        // @review epoch is indeed settled though there were some pending EigenLayer withdrawals
        assertEq(epochSummary.settled, true);
        console.log("Settled?", epochSummary.settled);
    }
```
## Impact
Withdrawal queue logic can be broken. EigenLayer withdrawal request can be stucked and never recovered.
## Code Snippet
https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTCoordinator.sol#L245-L267

https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTCoordinator.sol#L99-L151

https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/utils/OperatorOperations.sol#L113-L134

https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTWithdrawalQueue.sol#L177-L271

https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/restaking/RioLRTWithdrawalQueue.sol#L92-L108
## Tool used

Manual Review

## Recommendation
Do not let the start of new epoch when there is a pending EigenLayer withdrawal request. 

Do not let new withdrawal requests when there is a pending EigenLayer withdrawal request, if allowed, then account that there can be a pending EigenLayer withdrawal request at the time of user requesting a withdrawal.