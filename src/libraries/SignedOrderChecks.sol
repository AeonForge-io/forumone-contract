// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import {SafeCast} from "@openzeppelin/contracts/utils/math/SafeCast.sol";

import {IForumOne} from "../interfaces/IForumOne.sol";
import {MarketplaceStorage} from "./MarketplaceStorage.sol";
import {SignedOrders} from "./SignedOrders.sol";

/// @title SignedOrderChecks
/// @notice Everything a signed order must satisfy before the marketplace will settle it.
///
/// @dev External library, reached by `delegatecall`: it runs in the marketplace's storage context
///      (hence the `MarketplaceStorage storage` pointer — writing the fill count here writes the
///      proxy's state), and `msg.sender` is the marketplace call's caller, so the self-fill check
///      and the co-signature's fulfiller binding compare against the real caller.
///
///      The library address is linked into the implementation's bytecode; no storage slot and no
///      admin role can repoint it. Substituting these checks means deploying a new implementation
///      and going through `upgradeToAndCall` — the same authority needed to replace the
///      marketplace outright.
///
///      Split out of `ForumOne` to keep the implementation under the EIP-170 size limit. The
///      check order below is the order `docs/signed-orders-design.md` section 4 fixes.
library SignedOrderChecks {
    using SignedOrders for SignedOrders.SignedListing;
    using SignedOrders for SignedOrders.SignedOffer;

    // ============ Hashing ============

    /// @notice The EIP-712 type hash of the bulk listing wrapper for a tree of the given height.
    /// @dev Exposed so the signing service and a block-explorer reader can confirm the type string
    ///      the contract will hash is the one the wallet was shown. The marketplace facade
    ///      forwards to these; nothing on the fill path calls them.
    function bulkListingTypehash(uint256 height) external pure returns (bytes32) {
        return SignedOrders.bulkTypehash(height, false);
    }

    /// @notice The EIP-712 type hash of the bulk offer wrapper for a tree of the given height.
    function bulkOfferTypehash(uint256 height) external pure returns (bytes32) {
        return SignedOrders.bulkTypehash(height, true);
    }

    /// @notice The deepest bulk tree the contract will verify.
    function maxBulkOrderHeight() external pure returns (uint256) {
        return SignedOrders.MAX_BULK_ORDER_HEIGHT;
    }

    // ============ Verification ============

    /// @notice Runs every check a signed listing must pass, and records the fill.
    /// @dev Returns to the caller with only ownership, approval and settlement left to do. The fill
    ///      count is written here, before the marketplace makes any external call, so cumulative
    ///      fills can never exceed the signed quantity even under re-entry.
    /// @return orderHash The order's EIP-712 struct hash.
    /// @return filledToDate The cumulative quantity filled against this order after this fill.
    function checkSignedListing(
        MarketplaceStorage storage s,
        bytes32 domainSeparator,
        SignedOrders.SignedListing calldata order,
        bytes calldata signature,
        uint256 quantity,
        SignedOrders.Cosignature calldata cosig
    ) external returns (bytes32 orderHash, uint256 filledToDate) {
        orderHash = order.hash();

        _verifyOrderSignature(order.signer, domainSeparator, orderHash, signature, false);
        _verifyCosignature(s, domainSeparator, orderHash, cosig);

        filledToDate = _consumeOrder(s, order.signer, orderHash, order.counter, order.quantity, quantity);

        _validateOrderLifetime(s, orderHash, order.expiration);

        // The order carries its own fee and settlement charges exactly that, bounded only by the
        // platform ceiling. The co-signature is what vouches for the number.
        if (order.platformFeeBps > SignedOrders.MAX_PLATFORM_FEE_BPS) {
            revert IForumOne.OrderFeeTooHigh(order.platformFeeBps);
        }

        if (!s.approvedCollections[order.assetContract]) {
            revert IForumOne.CollectionNotApproved(order.assetContract);
        }
        if (s.pausedCollections[order.assetContract]) {
            revert IForumOne.CollectionPaused(order.assetContract);
        }
        if (msg.sender == order.signer) revert IForumOne.CannotFillOwnOrder(orderHash);
        if (quantity == 0) revert IForumOne.InvalidQuantity();
        if (order.pricePerToken == 0) revert IForumOne.ZeroPriceNotAllowed();
        if (order.currency != address(0) && !s.approvedCurrencies[order.currency]) {
            revert IForumOne.CurrencyNotApproved(order.currency);
        }
    }

    /// @notice Runs every check one acceptance of a signed offer must pass, and records the fill.
    /// @dev The offer fills in parts: this leg takes `accept.quantity` units of `accept.tokenId`,
    ///      counted against the order's `quantity` under its hash, and the count is written here
    ///      before the marketplace makes any external call. The token the seller offers is the
    ///      last check: it must be the order's own `tokenId`, or prove against the order's
    ///      criteria root — and a criteria offer must have been signed with `tokenId` zero.
    /// @return orderHash The order's EIP-712 struct hash.
    /// @return filledToDate The cumulative quantity filled against this order after this leg.
    function checkSignedOffer(
        MarketplaceStorage storage s,
        bytes32 domainSeparator,
        SignedOrders.SignedOfferAccept calldata accept
    ) external returns (bytes32 orderHash, uint256 filledToDate) {
        SignedOrders.SignedOffer calldata order = accept.order;
        orderHash = order.hash();

        _verifyOrderSignature(order.signer, domainSeparator, orderHash, accept.signature, true);
        _verifyCosignature(s, domainSeparator, orderHash, accept.cosig);

        filledToDate = _consumeOrder(s, order.signer, orderHash, order.counter, order.quantity, accept.quantity);

        _validateOrderLifetime(s, orderHash, order.expiration);

        if (order.platformFeeBps > SignedOrders.MAX_PLATFORM_FEE_BPS) {
            revert IForumOne.OrderFeeTooHigh(order.platformFeeBps);
        }

        if (!s.approvedCollections[order.assetContract]) {
            revert IForumOne.CollectionNotApproved(order.assetContract);
        }
        if (s.pausedCollections[order.assetContract]) {
            revert IForumOne.CollectionPaused(order.assetContract);
        }
        if (msg.sender == order.signer) revert IForumOne.CannotFillOwnOrder(orderHash);
        if (accept.quantity == 0) revert IForumOne.InvalidQuantity();
        if (order.pricePerToken == 0) revert IForumOne.ZeroPriceNotAllowed();
        if (order.currency == address(0)) revert IForumOne.OfferCurrencyMustBeERC20();
        if (!s.approvedCurrencies[order.currency]) {
            revert IForumOne.CurrencyNotApproved(order.currency);
        }

        // A criteria offer names no token: its `tokenId` is ignored on this path, so a nonzero
        // value is a malformed order, not a preference. Refused before eligibility so it is never
        // a question of which id the proof happened to cover.
        if (order.criteriaRoot != bytes32(0) && order.tokenId != 0) {
            revert IForumOne.CriteriaOfferNamesToken(orderHash);
        }

        if (!_isEligibleToken(order, accept.tokenId, accept.proof)) {
            revert IForumOne.OfferTokenNotEligible(orderHash, accept.tokenId);
        }
    }

    /// @dev An offer with no criteria root covers exactly its own `tokenId`. One with a root
    ///      covers every id whose leaf (`SignedOrders.criteriaLeaf`) proves against it; the
    ///      order's `tokenId` field is not consulted. `proof` is only read on the criteria path.
    function _isEligibleToken(SignedOrders.SignedOffer calldata order, uint256 tokenId, bytes32[] calldata proof)
        private
        pure
        returns (bool)
    {
        if (order.criteriaRoot == bytes32(0)) return tokenId == order.tokenId;
        return MerkleProof.verifyCalldata(proof, order.criteriaRoot, SignedOrders.criteriaLeaf(tokenId));
    }

    // ============ Internal ============

    /// @dev The maker's signature goes through `SignatureChecker`, which routes to `ECDSA` for a
    ///      signer with no code and to ERC-1271 for one with code. A Safe holding the NFT signs as
    ///      seller through ERC-1271, so the contract path is required — and contract signatures
    ///      are revocable, so an order can stop validating without anything on chain changing.
    ///
    ///      Two readings, tried in order. A signature longer than 65 bytes may be a bulk
    ///      signature — a leaf's proof up a Merkle tree of orders the maker signed in one go
    ///      (`SignedOrders.decodeBulkSignature`) — or an ordinary ERC-1271 blob that happens to be
    ///      that long; nothing in the bytes distinguishes the two. The bulk reading is attempted
    ///      first, and a failure falls through to verifying the whole blob against the
    ///      single-order digest. So a multi-owner Safe signature whose length collides with the
    ///      bulk shape still verifies, a 64- or 65-byte signature skips the bulk path entirely,
    ///      and a malformed or wrong-tree proof ends at the same `InvalidOrderSignature` as any
    ///      other bad signature.
    ///
    ///      Whichever reading wins, `orderHash` — the leaf — is what the rest of the fill uses.
    function _verifyOrderSignature(
        address signer,
        bytes32 domainSeparator,
        bytes32 orderHash,
        bytes calldata signature,
        bool isOffer
    ) private view {
        // The length gate is the only cost a single-order fill pays for bulk support: an ordinary
        // 64- or 65-byte signature fails it and goes straight to the single-order check.
        uint256 length = signature.length;
        if (length >= SignedOrders.MIN_BULK_SIGNATURE_LENGTH && length <= SignedOrders.MAX_BULK_SIGNATURE_LENGTH) {
            (bool bulkShaped, bytes32 bulkStructHash, bytes calldata innerSignature) =
                SignedOrders.decodeBulkSignature(orderHash, signature, isOffer);

            if (bulkShaped) {
                bytes32 bulkDigest = MessageHashUtils.toTypedDataHash(domainSeparator, bulkStructHash);
                if (SignatureChecker.isValidSignatureNowCalldata(signer, bulkDigest, innerSignature)) return;
            }
        }

        bytes32 digest = MessageHashUtils.toTypedDataHash(domainSeparator, orderHash);
        if (!SignatureChecker.isValidSignatureNowCalldata(signer, digest, signature)) {
            revert IForumOne.InvalidOrderSignature();
        }
    }

    /// @dev The platform attestation is ECDSA only: a contract signer would add an external call
    ///      to every fill and make fulfillment depend on a second contract's liveness. An
    ///      attestation is bound to one order hash, names its caller and expires in minutes, so
    ///      replaying one inside its window can only produce a fill the order already authorized —
    ///      which is why no used-attestation record is kept.
    function _verifyCosignature(
        MarketplaceStorage storage s,
        bytes32 domainSeparator,
        bytes32 orderHash,
        SignedOrders.Cosignature calldata cosig
    ) private view {
        bytes32 digest = MessageHashUtils.toTypedDataHash(
            domainSeparator, SignedOrders.hashFulfillmentAuthorization(orderHash, cosig.fulfiller, cosig.expiry)
        );

        address recovered = ECDSA.recover(digest, cosig.signature);
        if (!s.platformSigners[recovered]) revert IForumOne.UnauthorizedCosigner(recovered);

        if (cosig.expiry <= block.timestamp) revert IForumOne.CosignatureExpired(cosig.expiry);

        uint256 maxExpiry = block.timestamp + s.cosignatureValidity;
        if (cosig.expiry > maxExpiry) {
            revert IForumOne.CosignatureValidityExceeded(cosig.expiry, maxExpiry);
        }

        if (cosig.fulfiller != address(0) && cosig.fulfiller != msg.sender) {
            revert IForumOne.CosignatureFulfillerMismatch(cosig.fulfiller, msg.sender);
        }
    }

    /// @dev Checks the counter, the cancellation flag and what the order has left, then writes the
    ///      new fill count.
    function _consumeOrder(
        MarketplaceStorage storage s,
        address signer,
        bytes32 orderHash,
        uint256 orderCounter,
        uint256 orderQuantity,
        uint256 quantity
    ) private returns (uint256 filledToDate) {
        uint256 currentCounter = s.signerCounter[signer];
        if (orderCounter != currentCounter) {
            revert IForumOne.CounterMismatch(orderCounter, currentCounter);
        }

        IForumOne.SignedOrderStatus storage status = s.signedOrderStatus[SignedOrders.statusKey(signer, orderHash)];
        if (status.cancelled) revert IForumOne.OrderCancelled(orderHash);

        uint256 remaining = orderQuantity - status.filled;
        if (quantity > remaining) {
            revert IForumOne.OrderQuantityExceeded(orderHash, quantity, remaining);
        }

        filledToDate = uint256(status.filled) + quantity;
        status.filled = SafeCast.toUint248(filledToDate);
    }

    /// @dev An order must be live, and must not reach further into the future than
    ///      `maxOrderDuration` allows. The cap is the trustless backstop behind the service's
    ///      promise to stop attesting a superseded order.
    function _validateOrderLifetime(MarketplaceStorage storage s, bytes32 orderHash, uint256 expiration) private view {
        if (expiration <= block.timestamp) revert IForumOne.OrderExpired(orderHash);

        uint256 maxExpiration = block.timestamp + s.maxOrderDuration;
        if (expiration > maxExpiration) {
            revert IForumOne.OrderDurationTooLong(expiration, maxExpiration);
        }
    }
}
