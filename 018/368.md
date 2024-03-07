Rural Fiery Rattlesnake

high

# Unauthorized Withdrawal Claims in RioLRTWithdrawalQueue::claimWithdrawalsForEpoch function

## Summary
The RioLRTWithdrawalQueue contract currently lacks explicit verification mechanisms to ensure that the entity attempting to claim withdrawals is authorized to do so for the specified shares. This oversight could potentially allow unauthorized parties to claim assets that do not belong to them, leading to asset misappropriation and undermining the trust and security of the platform.

## Vulnerability Detail
The functions intended for withdrawal claims do not include checks to verify the identity of the caller against the intended recipient of the shares or assets. In decentralized systems, especially those involving financial transactions, it is crucial to enforce strict access controls to prevent unauthorized access to funds. The absence of such validations poses a significant security risk, as malicious actors might exploit this to withdraw assets they are not entitled to, thereby compromising the integrity and security of the contract and its users' assets.

## Impact
The `claimWithdrawalsForEpoch` function allows the caller to claim withdrawals without verifying if they are authorized to claim on behalf of the user whose shares are being withdrawn:

```solidity
function claimWithdrawalsForEpoch(ClaimRequest calldata request) public returns (uint256 amountOut) {
    // No explicit check to ensure the caller is authorized to claim these shares
    UserWithdrawalSummary memory userSummary = epochWithdrawals.users[request.withdrawer];
    if (userSummary.sharesOwed == 0) revert NO_SHARES_OWED_IN_EPOCH();
    if (userSummary.claimed) revert WITHDRAWAL_ALREADY_CLAIMED();
}
```
## Code Snippet
https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/restaking/RioLRTWithdrawalQueue.sol#L92

## Tool used

Manual Review

## Recommendation
Implement a check within the `claimWithdrawalsForEpoch` function to ensure that the caller is either the withdrawer or an authorized delegate:

```solidity
function claimWithdrawalsForEpoch(ClaimRequest calldata request) public returns (uint256 amountOut) {
    EpochWithdrawals storage epochWithdrawals = _getEpochWithdrawals(request.asset, request.epoch);
    require(epochWithdrawals.users[msg.sender].sharesOwed > 0 || authorizedDelegates[request.withdrawer][msg.sender], "Unauthorized claim");
    
    UserWithdrawalSummary storage userSummary = epochWithdrawals.users[request.withdrawer];
    if (userSummary.sharesOwed == 0) revert NO_SHARES_OWED_IN_EPOCH();
    if (userSummary.claimed) revert WITHDRAWAL_ALREADY_CLAIMED();
    
    // Additional logic to process the claim...
}
```

In this solution, `authorizedDelegates` is a mapping structure where users can register delegates authorized to claim withdrawals on their behalf:

```solidity
mapping(address => mapping(address => bool)) public authorizedDelegates;
```

This approach ensures that only the owner of the shares or an explicitly authorized delegate can initiate a claim, significantly enhancing the security of the withdrawal process and protecting against unauthorized access to funds.