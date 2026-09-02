// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/// @title ForumOneProxy
/// @notice An `ERC1967Proxy` under the project's own name, so the marketplace address verifies as
///         ForumOne rather than as OpenZeppelin's generic proxy.
/// @dev The explicit `receive` delegates exactly as the fallback would — a plain transfer reaches
///      the implementation's `receive` either way. It exists so this contract's runtime bytecode
///      differs from stock `ERC1967Proxy`: identical bytecode would make explorers and tooling
///      label the marketplace address with the generic name.
contract ForumOneProxy is ERC1967Proxy {
    constructor(address implementation, bytes memory data) payable ERC1967Proxy(implementation, data) {}

    receive() external payable {
        _fallback();
    }
}
