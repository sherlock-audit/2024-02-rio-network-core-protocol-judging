Obedient Carbon Leopard

high

# Mismatch in `QueuedWithdrawalParams` and `Withdrawal` structs between EigenLayer and Rio

## Summary
When requesting withdrawals the delegation manager expects an input called QueuedWithdrawalParams which the struct that the EigenLayer uses and the Rio uses are different, this will lead to withdrawals never go through. 
## Vulnerability Detail
First, let's see the queueWithdrawal function in the EigenLayer:
```solidity
function queueWithdrawals(
        -> QueuedWithdrawalParams[] calldata queuedWithdrawalParams
    ) external onlyWhenNotPaused(PAUSED_ENTER_WITHDRAWAL_QUEUE) returns (bytes32[] memory) {
        bytes32[] memory withdrawalRoots = new bytes32[](queuedWithdrawalParams.length);
        address operator = delegatedTo[msg.sender];

        for (uint256 i = 0; i < queuedWithdrawalParams.length; i++) {
            require(queuedWithdrawalParams[i].strategies.length == queuedWithdrawalParams[i].shares.length, "DelegationManager.queueWithdrawal: input length mismatch");
            require(queuedWithdrawalParams[i].withdrawer != address(0), "DelegationManager.queueWithdrawal: must provide valid withdrawal address");

            // Remove shares from staker's strategies and place strategies/shares in queue.
            // If the staker is delegated to an operator, the operator's delegated shares are also reduced
            // NOTE: This will fail if the staker doesn't have the shares implied by the input parameters
            withdrawalRoots[i] = _removeSharesAndQueueWithdrawal({
                staker: msg.sender,
                operator: operator,
                withdrawer: queuedWithdrawalParams[i].withdrawer,
                strategies: queuedWithdrawalParams[i].strategies,
                shares: queuedWithdrawalParams[i].shares
            });
        }
        return withdrawalRoots;
    }
```

As we can observe, the `QueuedWithdrawalParams` struct passed as input. Let's check the ingredients of the struct in the EigenLayer code:
```solidity
struct QueuedWithdrawalParams {
        // Array of strategies that the QueuedWithdrawal contains
        IStrategy[] strategies;
        // Array containing the amount of shares in each Strategy in the `strategies` array
        uint256[] shares;
        // The address of the withdrawer
        address withdrawer;
    }
```

Now, let's check Rio's `QueuedWithdrawalParams` struct:
```solidity
struct QueuedWithdrawalParams {
        // Array of strategies that the QueuedWithdrawal contains
        address[] strategies;
        // Array containing the amount of shares in each Strategy in the `strategies` array
        uint256[] shares;
        // The address of the withdrawer
        address withdrawer;
    }
```

as we can observe, the `strategies` parameter are different between the two structs. In actual deployment, the withdrawals will not be possible due to this mismatch because the EigenLayer expects `IStrategy` and the Rio sends `address`.

## Impact
Actual deployments withdrawals will not be possible. hence, core logic is broken.
## Code Snippet
https://github.com/Layr-Labs/eigenlayer-contracts/blob/6de01c6c16d6df44af15f0b06809dc160eac0ebf/src/contracts/core/DelegationManager.sol#L267-L289

https://github.com/Layr-Labs/eigenlayer-contracts/blob/6de01c6c16d6df44af15f0b06809dc160eac0ebf/src/contracts/interfaces/IDelegationManager.sol#L77-L101

https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/4f01e065c1ed346875cf5b05d2b43e0bcdb4c849/rio-sherlock-audit/contracts/interfaces/eigenlayer/IDelegationManager.sol#L68-L92
## Tool used

Manual Review

## Recommendation
Change the structs to EigenLayer version