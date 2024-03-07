Nutty Indigo Duck

medium

# rebalance() check that caller must be EOA may become ineffective which opens up attack vectors

## Summary
`(msg.sender != tx.origin)` may become an ineffective check if EIP 3074 goes live.

## Vulnerability Detail
In RioLRTCoordinator.sol, `rebalance()` requires caller to be an EOA:
```solidity
function rebalance(address asset) external checkRebalanceDelayMet(asset) {
        if (!assetRegistry().isSupportedAsset(asset)) revert ASSET_NOT_SUPPORTED(asset);
        if (msg.sender != tx.origin) revert CALLER_MUST_BE_EOA();
        ...
}
```

According to [EIP 3074](https://eips.ethereum.org/EIPS/eip-3074#allowing-txorigin-as-signer) : `AUTH` allows for signatures to be signed by `tx.origin`. For any such signatures, subsequent `AUTHCALLs` have `msg.sender == tx.origin` in their first layer of execution. Essentially, this delegates control of the EOA to a smart contract. 

Therefore, using `tx.origin` to ensure `msg.sender` is an EOA will not be effective if EIP 3074 goes live. There has been renewed interest in EIP 3074 and it was recently included in the [ACD agenda](https://github.com/ethereum/pm/issues/962) and discussions around the upcoming Prague upgrade. [Post meeting notes](https://notes.ethereum.org/QT9e9r6NRdSOjWRBzA3JLA#:~:text=EIP3074%20shines%20a%20little%20more%2C%20maintaining%20the%20op%20code%20is%20easier%20long%20term) also indicate that 3074 is a frontrunner for future improvements to account abstraction. 
 
## Impact
If EIP 3074 goes live it will open up attack vectors possible only through smart contracts. Consider this scenario where rewards can be stolen using a flash loan:
1. Take out an ETH flash loan.
2. Call deposit on the RioLRTCoordinator contract and deposit ETH until the deposit cap is reached, minting an equivalent amount of shares.
3. Execute [claimDelayedWithdrawal](https://github.com/Layr-Labs/eigenlayer-contracts/blob/v0.2.1-goerli-m2/src/contracts/pods/DelayedWithdrawalRouter.sol#L99) on Eigenlayer which sweeps funds through the Rio Network reward distributor and to the deposit pool.
4. Call the requestWithdrawal function of the RioLRTCoordinator contract, withdrawing the entire balance of the restaking token shares. Because the deposit pool contains sufficient funds, the withdrawal is immediately eligible for fulfillment.
5. Finalize the withdrawal by calling the rebalance function of the RioLRTCoordinator contract. Receive original deposit + majority of rewards (due to owning a large amount of shares at time of withdrawal request).
6. Repay flashloan.

## Code Snippet
https://github.com/sherlock-audit/2024-02-rio-network-core-protocol/blob/main/rio-sherlock-audit/contracts/restaking/RioLRTCoordinator.sol#L123

## Tool used
Manual Review

## Recommendation
Rio could consider other ways to check that caller is an EOA such as OpenZeppelin's `isContract`, but that too has a workaround if caller makes the call in the smart contract's constructor.

Instead, Rio should consider better ways to distribute rewards, as even without using a flashloan, users may time their deposits and withdrawals to only collect rewards without effectively staking. See also my other report titled "Attacker can deposit just before rewards are distributed and steal rewards".