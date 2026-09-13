// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IERC721} from "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import {IERC1155} from "@openzeppelin/contracts/token/ERC1155/IERC1155.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {IForumOne} from "../interfaces/IForumOne.sol";
import {MarketplaceStorage} from "./MarketplaceStorage.sol";
import {ForumOneSettlement, Settlement} from "./ForumOneSettlement.sol";

/// @title ForumOneOrders
/// @notice The stored listing and offer engine: creating, updating, cancelling and filling the
///         records that live on chain.
///
/// @dev External library, reached by `delegatecall`: it runs in the marketplace's storage context
///      (hence the `MarketplaceStorage storage` pointer on every function), `msg.sender` and
///      `msg.value` are the marketplace call's, so a seller check or a self-buy check here
///      compares against the real caller, and events emitted here carry the marketplace's
///      address.
///
///      The library address is linked into the implementation's bytecode; no storage slot and no
///      admin role can repoint the marketplace at different order logic. Substituting it means
///      deploying a new implementation and going through `upgradeToAndCall`.
///
///      Split out of `ForumOne` to keep the implementation under the EIP-170 size limit. Access
///      control, pausing and re-entrancy guarding stay on the marketplace's own entry points —
///      this library assumes it is only reached through them.
library ForumOneOrders {
    // ============ Listings ============

    function createListing(MarketplaceStorage storage s, IForumOne.ListingParameters calldata params)
        external
        returns (uint256 listingId)
    {
        if (!s.approvedCollections[params.assetContract]) {
            revert IForumOne.CollectionNotApproved(params.assetContract);
        }
        if (s.pausedCollections[params.assetContract]) {
            revert IForumOne.CollectionPaused(params.assetContract);
        }
        if (params.pricePerToken == 0) revert IForumOne.ZeroPriceNotAllowed();
        if (params.expiration <= block.timestamp) revert IForumOne.InvalidExpiration();
        if (params.quantity == 0) revert IForumOne.InvalidQuantity();
        if (params.currency != address(0) && !s.approvedCurrencies[params.currency]) {
            revert IForumOne.CurrencyNotApproved(params.currency);
        }

        IForumOne.TokenType tokenType = ForumOneSettlement.detectTokenType(s, params.assetContract);
        if (tokenType == IForumOne.TokenType.ERC721 && params.quantity != 1) {
            revert IForumOne.InvalidQuantity();
        }

        ForumOneSettlement.validateOwnershipAndApproval(
            msg.sender, params.assetContract, params.tokenId, params.quantity, tokenType
        );

        unchecked {
            listingId = s.nextListingId++;
        }
        IForumOne.Listing storage listing = s.listings[listingId];
        listing.listingId = listingId;
        listing.seller = msg.sender;
        listing.assetContract = params.assetContract;
        listing.tokenId = params.tokenId;
        listing.quantity = params.quantity;
        listing.currency = params.currency;
        listing.pricePerToken = params.pricePerToken;
        listing.expiration = params.expiration;
        listing.tokenType = tokenType;
        listing.status = IForumOne.ListingStatus.ACTIVE;
        _snapshotFeeTerms(s, listing, params.pricePerToken * params.quantity);

        emit IForumOne.ListingCreated(
            listingId,
            msg.sender,
            params.assetContract,
            params.tokenId,
            params.quantity,
            params.currency,
            params.pricePerToken,
            params.expiration,
            tokenType
        );
    }

    function updateListing(MarketplaceStorage storage s, uint256 listingId, IForumOne.ListingUpdate calldata params)
        external
    {
        IForumOne.Listing storage listing = s.listings[listingId];
        _requireActiveListing(listing, listingId);
        if (listing.seller != msg.sender) revert IForumOne.NotListingSeller(listingId, msg.sender);
        if (params.pricePerToken == 0) revert IForumOne.ZeroPriceNotAllowed();
        if (params.expiration <= block.timestamp) revert IForumOne.InvalidExpiration();
        if (params.currency != address(0) && !s.approvedCurrencies[params.currency]) {
            revert IForumOne.CurrencyNotApproved(params.currency);
        }

        ForumOneSettlement.validateOwnershipAndApproval(
            msg.sender, listing.assetContract, listing.tokenId, listing.quantity, listing.tokenType
        );

        listing.currency = params.currency;
        listing.pricePerToken = params.pricePerToken;
        listing.expiration = params.expiration;
        // The seller is re-committing to the listing, so it re-commits to the royalty and fee in
        // force now — the same moment they see the terms they are setting.
        _snapshotFeeTerms(s, listing, params.pricePerToken * listing.quantity);

        emit IForumOne.ListingUpdated(listingId, msg.sender, params);
    }

    /// @dev Fixes the platform fee and the royalty a stored listing will settle under, as of now:
    ///      the fee from storage and the royalty resolved exactly as settlement would resolve it
    ///      for `totalPrice`, expressed in basis points and capped at `10000 - platformFeeBps`
    ///      (`ForumOneSettlement.snapshotRoyalty`). Run at creation and at every update, so a
    ///      creator changing the override or the admin changing the fee afterwards cannot change
    ///      what the seller nets on a listing they already made.
    ///
    ///      `feeTermsSnapshotted` is set here and nowhere else: it is the record that this listing
    ///      committed to terms, and settlement reads it rather than guessing from the values. A
    ///      snapshot of zero fee and no royalty is a commitment like any other and is written as
    ///      one — the four fields alone cannot tell it from a listing that predates them.
    function _snapshotFeeTerms(MarketplaceStorage storage s, IForumOne.Listing storage listing, uint256 totalPrice)
        private
    {
        uint16 platformFeeBps = s.platformFeeBps;
        (address royaltyRecipient, uint16 royaltyBps) =
            ForumOneSettlement.snapshotRoyalty(s, listing.assetContract, listing.tokenId, totalPrice, platformFeeBps);
        listing.royaltyRecipient = royaltyRecipient;
        listing.royaltyBps = royaltyBps;
        listing.platformFeeBps = platformFeeBps;
        listing.feeTermsSnapshotted = true;
    }

    function cancelListing(MarketplaceStorage storage s, uint256 listingId) external {
        IForumOne.Listing storage listing = s.listings[listingId];
        _requireActiveListing(listing, listingId);
        if (listing.seller != msg.sender) revert IForumOne.NotListingSeller(listingId, msg.sender);

        listing.status = IForumOne.ListingStatus.CANCELLED;
        emit IForumOne.ListingCancelled(listingId, msg.sender);
    }

    /// @notice Cancels a listing whose seller no longer holds the listed token.
    /// @dev The unknown-id case is handled by `_requireActiveListing` — see its comment for why a
    ///      zero seller, not the status, is what identifies one.
    function cancelStaleListing(MarketplaceStorage storage s, uint256 listingId) external {
        IForumOne.Listing storage listing = s.listings[listingId];
        _requireActiveListing(listing, listingId);

        bool isStale;
        if (listing.tokenType == IForumOne.TokenType.ERC721) {
            try IERC721(listing.assetContract).ownerOf(listing.tokenId) returns (address owner) {
                isStale = owner != listing.seller;
            } catch {
                isStale = true;
            }
        } else {
            uint256 balance = IERC1155(listing.assetContract).balanceOf(listing.seller, listing.tokenId);
            isStale = balance < listing.quantity;
        }

        if (!isStale) revert IForumOne.ListingNotStale(listingId);

        listing.status = IForumOne.ListingStatus.CANCELLED;
        emit IForumOne.StaleListingCancelled(listingId, listing.seller, msg.sender);
    }

    /// @notice Fills one stored listing: checks, the record write, then settlement.
    /// @dev The buyer's terms are checked here, per leg, rather than in the facade: this is the
    ///      one place that reads the listing and computes what the fill will charge, and a stored
    ///      listing is read live, so `updateListing` can move its price and currency between the
    ///      buyer building the transaction and it landing. The listing's own checks stay in their
    ///      order; the terms check sits where `totalPrice` first exists.
    /// @param currency The currency the buyer accepted, `address(0)` for native.
    /// @param maxTotalPrice The most the buyer will pay for `quantity` units, in that currency.
    function executeBuy(
        MarketplaceStorage storage s,
        uint256 listingId,
        uint256 quantity,
        address currency,
        uint256 maxTotalPrice
    ) external {
        IForumOne.Listing storage listing = s.listings[listingId];

        _requireActiveListing(listing, listingId);
        if (listing.expiration <= block.timestamp) revert IForumOne.ListingExpired(listingId);
        if (!s.approvedCollections[listing.assetContract]) {
            revert IForumOne.CollectionNotApproved(listing.assetContract);
        }
        if (s.pausedCollections[listing.assetContract]) {
            revert IForumOne.CollectionPaused(listing.assetContract);
        }
        if (msg.sender == listing.seller) revert IForumOne.CannotBuyOwnListing(listingId);
        if (quantity == 0 || quantity > listing.quantity) revert IForumOne.InvalidQuantity();

        uint256 totalPrice = listing.pricePerToken * quantity;
        if (listing.currency != currency || totalPrice > maxTotalPrice) {
            revert IForumOne.ListingTermsChanged(listingId, listing.currency, totalPrice);
        }

        if (listing.currency != address(0) && !s.approvedCurrencies[listing.currency]) {
            revert IForumOne.CurrencyNotApproved(listing.currency);
        }

        if (quantity == listing.quantity) {
            listing.status = IForumOne.ListingStatus.SOLD;
        } else {
            listing.quantity -= quantity;
        }

        Settlement memory settlement;
        settlement.seller = listing.seller;
        settlement.buyer = msg.sender;
        settlement.assetContract = listing.assetContract;
        settlement.tokenId = listing.tokenId;
        settlement.quantity = quantity;
        settlement.tokenType = listing.tokenType;
        settlement.currency = listing.currency;
        settlement.totalPrice = totalPrice;
        // The listing settles under the fee and royalty it snapshotted when it was written, down
        // to and including a snapshot of nothing. A listing written before the snapshot fields
        // existed carries no flag and keeps settling at the live fee and royalty, as it did when
        // it was made.
        if (_hasFeeTermsSnapshot(listing)) {
            settlement.platformFeeBps = listing.platformFeeBps;
            settlement.royaltyFromSnapshot = true;
            settlement.royaltyRecipient = listing.royaltyRecipient;
            settlement.royaltyBps = listing.royaltyBps;
        } else {
            settlement.platformFeeBps = s.platformFeeBps;
        }

        (address royaltyRecipient, uint256 platformFeeAmount, uint256 royaltyAmount) =
            ForumOneSettlement.settle(s, settlement);

        emit IForumOne.Sale(
            listingId,
            listing.seller,
            msg.sender,
            listing.assetContract,
            listing.tokenId,
            quantity,
            totalPrice,
            listing.currency,
            platformFeeAmount,
            royaltyAmount,
            royaltyRecipient
        );
    }

    // ============ Offers ============

    function makeOffer(MarketplaceStorage storage s, IForumOne.OfferParameters calldata params)
        external
        returns (uint256 offerId)
    {
        if (!s.approvedCollections[params.assetContract]) {
            revert IForumOne.CollectionNotApproved(params.assetContract);
        }
        if (s.pausedCollections[params.assetContract]) {
            revert IForumOne.CollectionPaused(params.assetContract);
        }
        if (params.currency == address(0)) revert IForumOne.OfferCurrencyMustBeERC20();
        if (!s.approvedCurrencies[params.currency]) revert IForumOne.CurrencyNotApproved(params.currency);
        if (params.totalPrice == 0) revert IForumOne.ZeroPriceNotAllowed();
        if (params.expirationTimestamp <= block.timestamp) revert IForumOne.InvalidOfferExpiration();
        if (params.quantity == 0) revert IForumOne.InvalidQuantity();

        IForumOne.TokenType tokenType = ForumOneSettlement.detectTokenType(s, params.assetContract);
        if (tokenType == IForumOne.TokenType.ERC721 && params.quantity != 1) {
            revert IForumOne.InvalidQuantity();
        }

        unchecked {
            offerId = s.nextOfferId++;
        }
        s.offers[offerId] = IForumOne.Offer({
            offerId: offerId,
            offeror: msg.sender,
            assetContract: params.assetContract,
            tokenId: params.tokenId,
            quantity: params.quantity,
            currency: params.currency,
            totalPrice: params.totalPrice,
            expirationTimestamp: params.expirationTimestamp,
            tokenType: tokenType,
            status: IForumOne.OfferStatus.ACTIVE
        });

        emit IForumOne.OfferCreated(
            offerId,
            msg.sender,
            params.assetContract,
            params.tokenId,
            params.quantity,
            params.currency,
            params.totalPrice,
            params.expirationTimestamp,
            tokenType
        );
    }

    /// @notice Accepts one stored offer whole: checks, the record write, then settlement.
    /// @param minSellerProceeds The least the caller will net after the platform fee and the
    ///        royalty; settlement reverts `SellerProceedsBelowMinimum` below it. Zero disables it.
    function acceptOffer(MarketplaceStorage storage s, uint256 offerId, uint256 minSellerProceeds) external {
        IForumOne.Offer storage offer = s.offers[offerId];
        _requireActiveOffer(offer, offerId);
        if (offer.expirationTimestamp <= block.timestamp) revert IForumOne.OfferExpired(offerId);
        if (!s.approvedCollections[offer.assetContract]) {
            revert IForumOne.CollectionNotApproved(offer.assetContract);
        }
        if (s.pausedCollections[offer.assetContract]) {
            revert IForumOne.CollectionPaused(offer.assetContract);
        }
        if (!s.approvedCurrencies[offer.currency]) revert IForumOne.CurrencyNotApproved(offer.currency);
        if (msg.sender == offer.offeror) revert IForumOne.CannotAcceptOwnOffer(offerId);

        offer.status = IForumOne.OfferStatus.ACCEPTED;

        Settlement memory settlement;
        settlement.seller = msg.sender;
        settlement.buyer = offer.offeror;
        settlement.assetContract = offer.assetContract;
        settlement.tokenId = offer.tokenId;
        settlement.quantity = offer.quantity;
        settlement.tokenType = offer.tokenType;
        settlement.currency = offer.currency;
        settlement.totalPrice = offer.totalPrice;
        settlement.platformFeeBps = s.platformFeeBps;
        settlement.minSellerProceeds = minSellerProceeds;

        (address royaltyRecipient, uint256 platformFeeAmount, uint256 royaltyAmount) =
            ForumOneSettlement.settle(s, settlement);

        emit IForumOne.OfferAccepted(
            offerId,
            msg.sender,
            offer.offeror,
            offer.assetContract,
            offer.tokenId,
            offer.quantity,
            offer.totalPrice,
            offer.currency,
            platformFeeAmount,
            royaltyAmount,
            royaltyRecipient
        );
    }

    function cancelOffer(MarketplaceStorage storage s, uint256 offerId) external {
        IForumOne.Offer storage offer = s.offers[offerId];
        _requireActiveOffer(offer, offerId);
        if (offer.offeror != msg.sender) revert IForumOne.NotOfferor(offerId, msg.sender);

        offer.status = IForumOne.OfferStatus.CANCELLED;
        emit IForumOne.OfferCancelled(offerId, msg.sender);
    }

    /// @notice Cancels an offer the offeror can no longer honor.
    /// @dev The unknown-id case is handled by `_requireActiveOffer` — see its comment for why a
    ///      zero offeror, not the status, is what identifies one.
    function cancelStaleOffer(MarketplaceStorage storage s, uint256 offerId) external {
        IForumOne.Offer storage offer = s.offers[offerId];
        _requireActiveOffer(offer, offerId);

        uint256 balance = IERC20(offer.currency).balanceOf(offer.offeror);
        uint256 allowance = IERC20(offer.currency).allowance(offer.offeror, address(this));
        bool isStale = balance < offer.totalPrice || allowance < offer.totalPrice;

        if (!isStale) revert IForumOne.OfferNotStale(offerId);

        offer.status = IForumOne.OfferStatus.CANCELLED;
        emit IForumOne.StaleOfferCancelled(offerId, offer.offeror, msg.sender);
    }

    // ============ Internal: Record Validation ============

    /// @dev Whether the listing carries the fee terms it was written under — the flag `createListing`
    ///      and `updateListing` set, and nothing else. The snapshot fields were appended after
    ///      launch, so a listing created before that reads them as zero and reads the flag as false.
    ///
    ///      This used to be inferred from the values: no fee, no royalty and no recipient at once
    ///      meant "no snapshot". That misread the listing that legitimately snapshotted a zero
    ///      platform fee on a collection paying no royalty — a real commitment to settle free,
    ///      charged the live fee the moment the admin raised it. A snapshot of nothing is still a
    ///      snapshot, and only the flag can say so.
    function _hasFeeTermsSnapshot(IForumOne.Listing storage listing) private view returns (bool) {
        return listing.feeTermsSnapshotted;
    }

    /// @dev Reverts with `ListingNotActive` unless `listing` is a real, active record. A listing
    ///      that was never created reads back zeroed, and `ListingStatus.ACTIVE` is the enum's
    ///      zero value, so a zero seller — not the status — is what identifies an unknown id.
    ///      Every entry point runs this check first so an unknown id reverts here by name rather
    ///      than tripping a later check on the zeroed fields.
    function _requireActiveListing(IForumOne.Listing storage listing, uint256 listingId) private view {
        if (listing.seller == address(0) || listing.status != IForumOne.ListingStatus.ACTIVE) {
            revert IForumOne.ListingNotActive(listingId);
        }
    }

    /// @dev Reverts with `OfferNotActive` unless `offer` is a real, active record. An offer that
    ///      was never created reads back zeroed, and `OfferStatus.ACTIVE` is the enum's zero
    ///      value, so a zero offeror — not the status — is what identifies an unknown id. Every
    ///      entry point runs this check first so an unknown id reverts here by name rather than
    ///      tripping a later check on the zeroed fields.
    function _requireActiveOffer(IForumOne.Offer storage offer, uint256 offerId) private view {
        if (offer.offeror == address(0) || offer.status != IForumOne.OfferStatus.ACTIVE) {
            revert IForumOne.OfferNotActive(offerId);
        }
    }
}
