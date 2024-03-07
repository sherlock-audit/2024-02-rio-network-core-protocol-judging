Nutty Indigo Duck

high

# Deposits may be front-run by malicious operator to steal ETH

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
