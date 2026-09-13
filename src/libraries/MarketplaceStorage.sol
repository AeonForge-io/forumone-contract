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
    // v2. A collection whose creator has switched off the marketplace's unpaid transfer path
    // (`transferToken` / `batchTransferTokens`). Sales are unaffected. Appended, per the rule above.
    mapping(address => bool) transfersDisabled;
    // v2. Curator override for token standard resolution. 0 = auto-detect via ERC-165,
    // 1 = ERC-721, 2 = ERC-1155. Set for collections that misreport their standard — a contract
    // that behaves as an ERC-721 or ERC-1155 but whose `supportsInterface` does not say so, which
    // ERC-165 detection alone can never trade. Appended last, per the rule above.
    mapping(address => uint8) collectionTokenType;
}

library MarketplaceStorageLib {
    /// @notice No override: the collection's standard is resolved from its ERC-165 answers.
    /// @dev The stored default, so an untouched collection auto-detects exactly as it did before
    ///      the field existed. The `IForumOne.TokenType` enum cannot serve here — its zero value
    ///      is ERC721, so it has no "unset" state — which is why these are plain `uint8`s.
    uint8 internal constant TOKEN_TYPE_AUTO = 0;

    /// @notice Override: treat the collection as an ERC-721 whatever ERC-165 says.
    uint8 internal constant TOKEN_TYPE_ERC721 = 1;

    /// @notice Override: treat the collection as an ERC-1155 whatever ERC-165 says.
    uint8 internal constant TOKEN_TYPE_ERC1155 = 2;

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
