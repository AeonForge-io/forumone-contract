// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IForumOne} from "../interfaces/IForumOne.sol";

/// @notice The marketplace's entire persistent state.
/// @dev Declared at file level, not inside `ForumOne`, so the external libraries can take a
///      pointer to it. ERC-7201 fixes the base slot. New fields may only ever be appended —
///      never reorder or remove one.
/// @custom:storage-location erc7201:forumone.marketplace.storage
struct MarketplaceStorage {
    uint256 nextListingId;
    uint256 nextOfferId;
    address platformFeeRecipient;
    uint16 platformFeeBps;
    mapping(uint256 => IForumOne.Listing) listings;
    mapping(uint256 => IForumOne.Offer) offers;
    mapping(address => bool) approvedCollections;
    mapping(address => bool) pausedCollections;
    mapping(address => IForumOne.RoyaltyOverride) royaltyOverrides;
    mapping(address => bool) approvedCurrencies;
    // Signed-order state. ERC-7201 puts this struct at a fixed base slot with nothing laid out
    // after it, so appending fields is safe and no gap is needed.
    mapping(address => uint256) signerCounter;
    mapping(bytes32 => IForumOne.SignedOrderStatus) signedOrderStatus;
    mapping(address => bool) platformSigners;
    uint64 maxOrderDuration;
    uint64 cosignatureValidity;
}

library MarketplaceStorageLib {
    // keccak256(abi.encode(uint256(keccak256("forumone.marketplace.storage")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 internal constant MARKETPLACE_STORAGE_LOCATION =
        0x76e89683773470bc994bfbe09165380c5e3eea96c2d0b4859c7afa5f710b7d00;

    function layout() internal pure returns (MarketplaceStorage storage $) {
        bytes32 location = MARKETPLACE_STORAGE_LOCATION;
        assembly {
            $.slot := location
        }
    }
}
