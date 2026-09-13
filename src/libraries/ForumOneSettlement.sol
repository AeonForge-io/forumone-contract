// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {IERC721} from "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import {IERC1155} from "@openzeppelin/contracts/token/ERC1155/IERC1155.sol";
import {IERC2981} from "@openzeppelin/contracts/interfaces/IERC2981.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

import {IForumOne} from "../interfaces/IForumOne.sol";
import {MarketplaceStorage, MarketplaceStorageLib} from "./MarketplaceStorage.sol";

/// @notice The arguments of one settled trade, gathered so `settle` takes a single stack slot.
/// @dev `platformFeeBps` is passed in rather than read from storage because a signed order carries
///      the fee it was signed under (see `docs/signed-orders-design.md` section 2) and a stored
///      listing carries the fee it was created under; the stored offer path passes
///      `s.platformFeeBps`. `royaltyFromSnapshot` says the royalty was fixed when the record was
///      written (a stored listing): settlement then pays `totalPrice * royaltyBps / 10000` to
///      `royaltyRecipient` instead of resolving the royalty live. `minSellerProceeds` is the
///      seller's floor on their net; zero on the buy paths, where the seller is not the caller.
struct Settlement {
    address seller;
    address buyer;
    address assetContract;
    uint256 tokenId;
    uint256 quantity;
    IForumOne.TokenType tokenType;
    address currency;
    uint256 totalPrice;
    uint16 platformFeeBps;
    bool royaltyFromSnapshot;
    address royaltyRecipient;
    uint16 royaltyBps;
    uint256 minSellerProceeds;
}

/// @title ForumOneSettlement
/// @notice Token-standard detection, ownership and approval checks, token movement, and the split
///         of a sale price between platform, creator and seller.
///
/// @dev External library, reached by `delegatecall`: it runs in the marketplace's storage context
///      (hence the `MarketplaceStorage storage` pointer), native payouts spend the marketplace's
///      balance, and `msg.sender` is the marketplace call's caller throughout.
///
///      The library address is linked into the implementation's bytecode; no storage slot names
///      it and no admin role can repoint it. Replacing this logic means deploying a new
///      implementation and going through `upgradeToAndCall`.
///
///      Split out of `ForumOne` to keep the implementation under the EIP-170 size limit.
library ForumOneSettlement {
    using SafeERC20 for IERC20;

    uint256 private constant BPS_DENOMINATOR = 10_000;

    /// @notice The most gas any read of a collection — `royaltyInfo`, `owner()`, `hasRole` — may
    ///         consume.
    /// @dev A hostile collection could otherwise burn the whole transaction's gas in a view and
    ///      make every sale of itself fail for the caller's account. 250k is two orders of
    ///      magnitude above what an honest implementation needs and small next to a fill.
    uint256 internal constant EXTERNAL_READ_GAS = 250_000;

    /// @notice The tail every sale shares: confirm the seller can still deliver, move the token,
    ///         then split the price.
    /// @dev Callers write their own record first — a listing's status or remaining quantity, an
    ///      offer's status, a signed order's fill count — so the trade is already settled in
    ///      storage before this function makes any external call.
    function settle(MarketplaceStorage storage s, Settlement memory settlement)
        external
        returns (address royaltyRecipient, uint256 platformFeeAmount, uint256 royaltyAmount)
    {
        _validateOwnershipAndApproval(
            settlement.seller, settlement.assetContract, settlement.tokenId, settlement.quantity, settlement.tokenType
        );

        _transferToken(
            settlement.seller,
            settlement.buyer,
            settlement.assetContract,
            settlement.tokenId,
            settlement.quantity,
            settlement.tokenType
        );

        (royaltyRecipient, platformFeeAmount, royaltyAmount) = _payout(s, settlement);
    }

    /// @notice Resolves which token standard a collection speaks.
    /// @dev The curator's override wins over the collection's ERC-165 answers; see
    ///      `_resolveTokenType`. Reverts `TokenTypeNotSupported` when nothing resolves.
    function detectTokenType(MarketplaceStorage storage s, address assetContract)
        external
        view
        returns (IForumOne.TokenType)
    {
        return _detectTokenType(s, assetContract);
    }

    /// @notice What the marketplace will conclude for a collection, without reverting.
    /// @dev The same resolution every trading path runs, reported as `0` (nothing resolves),
    ///      `1` (ERC-721) or `2` (ERC-1155) instead of a revert, so a caller can ask before
    ///      committing. It shares `_resolveTokenType` with `_detectTokenType` rather than
    ///      replicating the probes, so the answer and the behaviour can never drift apart.
    ///      Never reverts, for any address — an EOA, an empty address, or a contract with no
    ///      `supportsInterface` at all all answer `0`.
    function previewTokenType(MarketplaceStorage storage s, address collection) external view returns (uint8) {
        return _resolveTokenType(s, collection);
    }

    /// @notice Confirms `owner` still holds the tokens and the marketplace may still move them.
    function validateOwnershipAndApproval(
        address owner,
        address assetContract,
        uint256 tokenId,
        uint256 quantity,
        IForumOne.TokenType tokenType
    ) external view {
        _validateOwnershipAndApproval(owner, assetContract, tokenId, quantity, tokenType);
    }

    /// @notice The royalty a stored listing will settle under, fixed when the listing is written.
    /// @dev Resolves the royalty exactly as `settle` would at this moment — the collection's
    ///      override if one is set, else its ERC-2981 answer through the same guarded read — for
    ///      the listing's whole `totalPrice`, and expresses it in basis points so a partial fill
    ///      of an ERC-1155 listing pays its share. An override is already in basis points and is
    ///      taken as is; an ERC-2981 amount becomes `floor(amount * 10000 / totalPrice)`, which
    ///      can be up to one basis point below what the collection asked (the seller's favour).
    ///      Capped at `10000 - platformFeeBps`, the same ceiling `_payout` clamps to, so the
    ///      snapshot never promises more than settlement would pay. No royalty — no recipient or
    ///      no amount — is `(address(0), 0)`.
    /// @param platformFeeBps The platform fee the listing is snapshotting alongside.
    function snapshotRoyalty(
        MarketplaceStorage storage s,
        address assetContract,
        uint256 tokenId,
        uint256 totalPrice,
        uint16 platformFeeBps
    ) external view returns (address recipient, uint16 royaltyBps) {
        IForumOne.RoyaltyOverride storage override_ = s.royaltyOverrides[assetContract];

        uint256 bps;
        if (override_.isSet) {
            recipient = override_.recipient;
            bps = override_.feeBps;
        } else {
            uint256 amount;
            (recipient, amount) = _readRoyaltyInfo(assetContract, tokenId, totalPrice);
            // An answer at or above the whole price is the whole price; comparing first keeps an
            // absurd answer from overflowing the conversion and refusing the listing.
            bps = amount >= totalPrice ? BPS_DENOMINATOR : (amount * BPS_DENOMINATOR) / totalPrice;
        }

        uint256 ceiling = BPS_DENOMINATOR - platformFeeBps;
        if (bps > ceiling) bps = ceiling;
        if (recipient == address(0) || bps == 0) return (address(0), 0);

        // casting to 'uint16' is safe because bps was just capped at BPS_DENOMINATOR (10000)
        // forge-lint: disable-next-line(unsafe-typecast)
        royaltyBps = uint16(bps);
    }

    /// @notice One leg of a peer-to-peer transfer: the collection checks, the standard, the
    ///         ownership and approval check, the move, and the event.
    /// @dev `transferToken` and `batchTransferTokens` share this, so a batch leg can never be
    ///      checked differently from a single transfer. The event is emitted from here; under
    ///      `delegatecall` that means it is emitted by the marketplace.
    function transferLeg(
        MarketplaceStorage storage s,
        address from,
        address to,
        address assetContract,
        uint256 tokenId,
        uint256 quantity
    ) public {
        if (!s.approvedCollections[assetContract]) {
            revert IForumOne.CollectionNotApproved(assetContract);
        }
        if (s.pausedCollections[assetContract]) revert IForumOne.CollectionPaused(assetContract);
        // The creator's switch on this one unpaid path. A sale of the same collection is never
        // gated by it: settlement does not come through here.
        if (s.transfersDisabled[assetContract]) revert IForumOne.CollectionTransfersDisabled(assetContract);

        IForumOne.TokenType tokenType = _detectTokenType(s, assetContract);
        if (tokenType == IForumOne.TokenType.ERC721 && quantity != 1) {
            revert IForumOne.InvalidQuantity();
        }
        if (quantity == 0) revert IForumOne.InvalidQuantity();

        _validateOwnershipAndApproval(from, assetContract, tokenId, quantity, tokenType);
        _transferToken(from, to, assetContract, tokenId, quantity, tokenType);

        emit IForumOne.TokenTransferred(from, to, assetContract, tokenId, quantity, tokenType);
    }

    // ============ Collection Manager ============

    /// @notice Whether `account` may change a collection's per-collection settings on the
    ///         marketplace — its royalty override and its transfer lock.
    /// @dev The rule is the one Limit Break's transfer validator uses for its own settings, so a
    ///      creator who can configure their collection elsewhere can configure it here with the
    ///      same wallet: the collection's `owner()` (Ownable), or a holder of the collection's
    ///      `DEFAULT_ADMIN_ROLE` (AccessControl). Only a collection with no resolvable owner — no
    ///      `owner()` at all, or one that answers zero — falls back to the marketplace curator,
    ///      which is why the caller's curator standing is passed in rather than read here.
    ///
    ///      Both reads are raw `staticcall`s decoded by hand, like the ERC-2981 read below, so a
    ///      collection that implements neither, or answers garbage, simply does not grant. Each
    ///      forwards at most `EXTERNAL_READ_GAS` and copies at most one word back, so a hostile
    ///      collection can neither burn the caller's gas nor return-data-bomb the check. The role
    ///      path carries a sentinel: a collection whose `hasRole` grants the default admin role to
    ///      `address(0)` answers true for anyone, so its role answers are meaningless and only its
    ///      `owner()` counts. The marketplace's own admin role grants nothing: these settings
    ///      belong to the creator.
    /// @param collection The collection whose settings are in question.
    /// @param account The would-be manager.
    /// @param isCurator Whether `account` holds the marketplace's CURATOR_ROLE.
    function isCollectionManager(address collection, address account, bool isCurator) external view returns (bool) {
        (bool hasOwner, address owner) = _readOwner(collection);
        if (hasOwner && owner == account) return true;

        if (_hasDefaultAdminRole(collection, account)) return true;

        return !hasOwner && isCurator;
    }

    /// @dev `owner()` through a bounded `staticcall`. `hasOwner` is false when the call fails,
    ///      when fewer than 32 bytes come back, when the word is not a clean address, or when the
    ///      address is zero (an Ownable whose owner renounced): every one of those is "no owner".
    function _readOwner(address collection) private view returns (bool hasOwner, address owner) {
        (bool success, uint256 word) = _staticcallWord(collection, abi.encodeWithSignature("owner()"));
        if (!success) return (false, address(0));
        if (word == 0 || word > type(uint160).max) return (false, address(0));

        // casting to 'uint160' is safe because the check above rejected any word with
        // nonzero upper 12 bytes, so no value can be truncated here
        // forge-lint: disable-next-line(unsafe-typecast)
        return (true, address(uint160(word)));
    }

    /// @dev `hasRole(bytes32(0), account)` through a bounded `staticcall`, guarded by the
    ///      sentinel: if the collection also grants the role to `address(0)` — which no honest
    ///      AccessControl does — its answers mean nothing and the role path grants nobody.
    function _hasDefaultAdminRole(address collection, address account) private view returns (bool) {
        if (_hasRole(collection, address(0))) return false;
        return _hasRole(collection, account);
    }

    /// @dev One `hasRole(bytes32(0), account)` read: true only for a clean 32-byte `true`.
    ///      AccessControl's DEFAULT_ADMIN_ROLE is `0x00`.
    function _hasRole(address collection, address account) private view returns (bool) {
        (bool success, uint256 word) =
            _staticcallWord(collection, abi.encodeWithSignature("hasRole(bytes32,address)", bytes32(0), account));
        return success && word == 1;
    }

    /// @dev A `staticcall` that forwards at most `EXTERNAL_READ_GAS` and reads back at most one
    ///      word. `success` is false when the call fails or returns fewer than 32 bytes; `word`
    ///      is the first word of the return data otherwise. Only that word is ever copied, so the
    ///      size of what the callee returns costs the caller nothing.
    function _staticcallWord(address target, bytes memory callData) private view returns (bool success, uint256 word) {
        assembly ("memory-safe") {
            // The scratch space holds the one word of output.
            success := staticcall(EXTERNAL_READ_GAS, target, add(callData, 0x20), mload(callData), 0x00, 0x20)
            if lt(returndatasize(), 0x20) { success := 0 }
            word := mload(0x00)
        }
    }

    /// @notice Every leg of a batch transfer, to one recipient, all or nothing.
    /// @dev The call-level checks — zero recipient, self-transfer, batch cap — stay in the
    ///      marketplace; this is the loop.
    function batchTransfer(
        MarketplaceStorage storage s,
        address from,
        address to,
        IForumOne.TransferLeg[] calldata legs
    ) external {
        for (uint256 i = 0; i < legs.length;) {
            IForumOne.TransferLeg calldata leg = legs[i];
            transferLeg(s, from, to, leg.assetContract, leg.tokenId, leg.quantity);
            unchecked {
                ++i;
            }
        }
    }

    /// @notice Moves tokens of either standard from one holder to another.
    function transferToken(
        address from,
        address to,
        address assetContract,
        uint256 tokenId,
        uint256 quantity,
        IForumOne.TokenType tokenType
    ) external {
        _transferToken(from, to, assetContract, tokenId, quantity, tokenType);
    }

    // ============ Internal: Token Detection ============

    /// @dev The resolution every path that moves a token runs. `_resolveTokenType` is the whole
    ///      of it; this only turns its answer into the enum, or into the revert that says no
    ///      standard resolved.
    function _detectTokenType(MarketplaceStorage storage s, address assetContract)
        private
        view
        returns (IForumOne.TokenType)
    {
        uint8 resolved = _resolveTokenType(s, assetContract);
        if (resolved == MarketplaceStorageLib.TOKEN_TYPE_ERC1155) return IForumOne.TokenType.ERC1155;
        if (resolved == MarketplaceStorageLib.TOKEN_TYPE_ERC721) return IForumOne.TokenType.ERC721;

        revert IForumOne.TokenTypeNotSupported(assetContract);
    }

    /// @dev The one place the standard is decided, shared by `_detectTokenType` and by
    ///      `previewTokenType` so the marketplace's stated conclusion is its actual one.
    ///
    ///      Order:
    ///        1. the curator's override, `s.collectionTokenType[assetContract]`: 1 is ERC-721,
    ///           2 is ERC-1155, and it wins outright — the collection is not asked anything.
    ///           That is the point: a collection whose `supportsInterface` misreports its own
    ///           standard (answering false for both, or answering for the wrong one) is
    ///           untradeable otherwise, and ERC-165 is not the authority here, the curator is.
    ///        2. otherwise the collection's own ERC-165 answers, ERC-1155 first then ERC-721,
    ///           exactly as before the override existed. A probe that reverts, runs out of gas
    ///           or returns undecodable data is a "no" and never propagates.
    ///        3. otherwise `TOKEN_TYPE_AUTO` — nothing resolved.
    ///
    ///      Returns, never reverts — which is why an address with no code is checked for before
    ///      the probes rather than left to the `catch`. `try` does not catch it: the compiler's
    ///      own `extcodesize` guard in front of a call that expects return data reverts before
    ///      the call is made, so an EOA or an empty address would otherwise take the whole
    ///      transaction down with an undecodable revert. Nothing there can answer ERC-165, so it
    ///      resolves to nothing — `previewTokenType` says `0` and the trading paths say
    ///      `TokenTypeNotSupported`, naming the address, instead.
    function _resolveTokenType(MarketplaceStorage storage s, address assetContract) private view returns (uint8) {
        uint8 pinned = s.collectionTokenType[assetContract];
        if (pinned == MarketplaceStorageLib.TOKEN_TYPE_ERC721) return MarketplaceStorageLib.TOKEN_TYPE_ERC721;
        if (pinned == MarketplaceStorageLib.TOKEN_TYPE_ERC1155) return MarketplaceStorageLib.TOKEN_TYPE_ERC1155;

        if (assetContract.code.length == 0) return MarketplaceStorageLib.TOKEN_TYPE_AUTO;

        try IERC165(assetContract).supportsInterface(type(IERC1155).interfaceId) returns (bool isERC1155) {
            if (isERC1155) return MarketplaceStorageLib.TOKEN_TYPE_ERC1155;
        } catch {}

        try IERC165(assetContract).supportsInterface(type(IERC721).interfaceId) returns (bool isERC721) {
            if (isERC721) return MarketplaceStorageLib.TOKEN_TYPE_ERC721;
        } catch {}

        return MarketplaceStorageLib.TOKEN_TYPE_AUTO;
    }

    // ============ Internal: Ownership Validation ============

    function _validateOwnershipAndApproval(
        address owner,
        address assetContract,
        uint256 tokenId,
        uint256 quantity,
        IForumOne.TokenType tokenType
    ) private view {
        if (tokenType == IForumOne.TokenType.ERC721) {
            address tokenOwner = IERC721(assetContract).ownerOf(tokenId);
            if (tokenOwner != owner) revert IForumOne.CallerNotOwner(tokenId, owner);
            address approved = IERC721(assetContract).getApproved(tokenId);
            if (approved != address(this) && !IERC721(assetContract).isApprovedForAll(owner, address(this))) {
                revert IForumOne.MarketplaceNotApproved(owner, assetContract);
            }
        } else {
            uint256 balance = IERC1155(assetContract).balanceOf(owner, tokenId);
            if (balance < quantity) {
                revert IForumOne.InsufficientTokenBalance(owner, tokenId, quantity, balance);
            }
            if (!IERC1155(assetContract).isApprovedForAll(owner, address(this))) {
                revert IForumOne.MarketplaceNotApproved(owner, assetContract);
            }
        }
    }

    // ============ Internal: Token Transfer ============

    function _transferToken(
        address from,
        address to,
        address assetContract,
        uint256 tokenId,
        uint256 quantity,
        IForumOne.TokenType tokenType
    ) private {
        if (tokenType == IForumOne.TokenType.ERC1155) {
            IERC1155(assetContract).safeTransferFrom(from, to, tokenId, quantity, "");
        } else {
            IERC721(assetContract).safeTransferFrom(from, to, tokenId);
        }
    }

    // ============ Internal: Payment Distribution ============

    /// @dev The platform fee is taken first. Whatever the royalty source asks for — a creator
    ///      override, an ERC-2981 answer, or a stored listing's snapshot alike — is clamped to
    ///      `totalPrice - platformFeeAmount`, so a sale never reverts over the royalty amount and
    ///      the seller may legitimately net zero. The fee comes from the settlement, not from
    ///      storage, because a signed order carries the fee it was signed under and a stored
    ///      listing the fee it was created under; the clamp follows whichever value was passed,
    ///      so fee plus royalty never exceeds the price either way. The seller's floor is checked
    ///      once the net is known and before anything moves.
    function _payout(MarketplaceStorage storage s, Settlement memory settlement)
        private
        returns (address royaltyRecipient, uint256 platformFeeAmount, uint256 royaltyAmount)
    {
        uint256 totalPrice = settlement.totalPrice;

        platformFeeAmount = (totalPrice * settlement.platformFeeBps) / BPS_DENOMINATOR;

        if (settlement.royaltyFromSnapshot) {
            royaltyRecipient = settlement.royaltyRecipient;
            royaltyAmount = (totalPrice * settlement.royaltyBps) / BPS_DENOMINATOR;
        } else {
            (royaltyRecipient, royaltyAmount) =
                _resolveRoyalty(s, settlement.assetContract, settlement.tokenId, totalPrice);
        }

        uint256 maxRoyalty = totalPrice - platformFeeAmount;
        if (royaltyAmount > maxRoyalty) {
            royaltyAmount = maxRoyalty;
        }

        // Unreachable after the clamp above; kept as a named guard on the invariant.
        if (platformFeeAmount + royaltyAmount > totalPrice) {
            revert IForumOne.TotalFeesExceedPrice(platformFeeAmount + royaltyAmount, totalPrice);
        }

        uint256 sellerProceeds = totalPrice - platformFeeAmount - royaltyAmount;
        if (sellerProceeds < settlement.minSellerProceeds) {
            revert IForumOne.SellerProceedsBelowMinimum(sellerProceeds, settlement.minSellerProceeds);
        }

        _transferCurrency(settlement.currency, settlement.buyer, s.platformFeeRecipient, platformFeeAmount);
        if (royaltyAmount > 0) {
            _transferCurrency(settlement.currency, settlement.buyer, royaltyRecipient, royaltyAmount);
        }
        _transferCurrency(settlement.currency, settlement.buyer, settlement.seller, sellerProceeds);
    }

    // ============ Internal: Royalty Resolution ============

    /// @dev A creator-set override always wins; only when none is set is the collection asked for
    ///      an ERC-2981 answer through `_readRoyaltyInfo`. The returned amount is not yet
    ///      clamped; `_payout` applies the `price - platformFeeAmount` ceiling. The stored
    ///      listing path does not come through here: it resolved its royalty with
    ///      `snapshotRoyalty` when the listing was written and settles from that.
    function _resolveRoyalty(MarketplaceStorage storage s, address assetContract, uint256 tokenId, uint256 salePrice)
        private
        view
        returns (address recipient, uint256 amount)
    {
        IForumOne.RoyaltyOverride storage override_ = s.royaltyOverrides[assetContract];

        if (override_.isSet) {
            recipient = override_.recipient;
            amount = (salePrice * override_.feeBps) / BPS_DENOMINATOR;
            return (recipient, amount);
        }

        return _readRoyaltyInfo(assetContract, tokenId, salePrice);
    }

    /// @dev The guarded ERC-2981 read that settlement and the listing snapshot share. A bounded
    ///      `staticcall` — at most `EXTERNAL_READ_GAS` forwarded, at most 64 bytes copied back —
    ///      decoded by hand so nothing a collection returns, and no amount of gas it burns, can
    ///      revert the sale. Falls through to no royalty (`address(0)`, `0`) when:
    ///        - the `staticcall` fails (revert, out of gas, or a non-contract address);
    ///        - fewer than 64 bytes of return data (64 or more: the first two words are read and
    ///          the rest ignored);
    ///        - the recipient word has nonzero upper bits (not a clean address);
    ///        - the decoded recipient is `address(0)`, or the amount is zero.
    ///      A collection with a broken or hostile `royaltyInfo` therefore stays tradeable.
    function _readRoyaltyInfo(address assetContract, uint256 tokenId, uint256 salePrice)
        private
        view
        returns (address recipient, uint256 amount)
    {
        bytes memory callData = abi.encodeCall(IERC2981.royaltyInfo, (tokenId, salePrice));

        bool success;
        uint256 recipientWord;
        uint256 amountWord;
        assembly ("memory-safe") {
            // Two words of output land at the free memory pointer, used as scratch and never
            // allocated: nothing here outlives the block.
            let out := mload(0x40)
            success := staticcall(EXTERNAL_READ_GAS, assetContract, add(callData, 0x20), mload(callData), out, 0x40)
            if lt(returndatasize(), 0x40) { success := 0 }
            recipientWord := mload(out)
            amountWord := mload(add(out, 0x20))
        }

        if (!success) return (address(0), 0);

        // Dirty upper bits mean the collection did not return a clean address word.
        if (recipientWord > type(uint160).max) return (address(0), 0);
        if (amountWord == 0) return (address(0), 0);

        // casting to 'uint160' is safe because the check above rejected any word with
        // nonzero upper 12 bytes, so no value can be truncated here
        // forge-lint: disable-next-line(unsafe-typecast)
        address decodedRecipient = address(uint160(recipientWord));
        if (decodedRecipient == address(0)) return (address(0), 0);

        return (decodedRecipient, amountWord);
    }

    // ============ Internal: Currency Transfer ============

    function _transferCurrency(address currency, address from, address to, uint256 amount) private {
        if (amount == 0) return;

        if (currency == address(0)) {
            (bool success,) = to.call{value: amount}("");
            if (!success) revert IForumOne.NativeTransferFailed(to, amount);
        } else {
            if (from == address(this)) {
                IERC20(currency).safeTransfer(to, amount);
            } else {
                IERC20(currency).safeTransferFrom(from, to, amount);
            }
        }
    }
}
