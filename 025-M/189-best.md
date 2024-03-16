Bouncy Raisin Crow

medium

# RioLRTIssuer::issueLRT reverts if deposit asset's approve method doesn't return a bool

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
