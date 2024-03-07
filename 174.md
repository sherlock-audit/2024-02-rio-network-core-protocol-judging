Energetic Turquoise Quail

high

# Execution Layer rewards are lost

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
