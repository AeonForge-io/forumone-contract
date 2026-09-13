// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {SignedOrders} from "../libraries/SignedOrders.sol";

interface IForumOne {
    // ============ Enums ============

    enum TokenType {
        ERC721,
        ERC1155
    }

    enum ListingStatus {
        ACTIVE,
        SOLD,
        CANCELLED
    }

    enum OfferStatus {
        ACTIVE,
        ACCEPTED,
        CANCELLED
    }

    // ============ Structs ============

    struct ListingParameters {
        address assetContract;
        uint256 tokenId;
        uint256 quantity;
        address currency;
        uint256 pricePerToken;
        uint128 expiration;
    }

    struct ListingUpdate {
        address currency;
        uint256 pricePerToken;
        uint128 expiration;
    }

    /// @notice A stored listing, with the royalty and platform fee it will settle under.
    /// @dev `royaltyRecipient` / `royaltyBps` / `platformFeeBps` are the listing's snapshot of its
    ///      fee terms, taken at `createListing` and again at `updateListing`: `platformFeeBps` is
    ///      the platform fee in force at that moment, and `royaltyRecipient` / `royaltyBps` are the
    ///      royalty resolved exactly as settlement would have resolved it then — the collection's
    ///      override if one was set, else its ERC-2981 answer for `pricePerToken * quantity` —
    ///      converted to basis points and capped at `10000 - platformFeeBps`. A stored buy settles
    ///      from the snapshot, so neither a later `setRoyaltyOverride` nor a later `setPlatformFee`
    ///      can change what the seller nets on a listing they already made.
    ///
    ///      `feeTermsSnapshotted` is what says the snapshot was taken, and it is the only thing
    ///      settlement consults. True: the three fields above are binding exactly as written, and a
    ///      snapshot of no fee and no royalty is as binding as any other — the listing settles free
    ///      however the live fee moves afterwards. False: the record predates the snapshot fields,
    ///      reads them all as zero, and settles at the live royalty and fee as it did when it was
    ///      made. The flag exists because those two cases are otherwise the same four zeros, and
    ///      inferring the answer from them charged a post-upgrade zero-fee listing the live fee.
    ///
    ///      Storage layout: this struct lives in mapping storage under ERC-7201, so fields may only
    ///      ever be APPENDED — never reordered, never removed. `feeTermsSnapshotted` must stay last
    ///      appended; anything new goes after it.
    struct Listing {
        uint256 listingId;
        address seller;
        address assetContract;
        uint256 tokenId;
        uint256 quantity;
        address currency;
        uint256 pricePerToken;
        uint128 expiration;
        TokenType tokenType;
        ListingStatus status;
        address royaltyRecipient;
        uint16 royaltyBps;
        uint16 platformFeeBps;
        bool feeTermsSnapshotted;
    }

    struct OfferParameters {
        address assetContract;
        uint256 tokenId;
        uint256 quantity;
        address currency;
        uint256 totalPrice;
        uint128 expirationTimestamp;
    }

    struct Offer {
        uint256 offerId;
        address offeror;
        address assetContract;
        uint256 tokenId;
        uint256 quantity;
        address currency;
        uint256 totalPrice;
        uint128 expirationTimestamp;
        TokenType tokenType;
        OfferStatus status;
    }

    struct RoyaltyOverride {
        address recipient;
        uint16 feeBps;
        bool isSet;
    }

    /// @notice One token movement in a `batchTransferTokens` call.
    /// @dev No per-leg recipient: the call takes one recipient for every leg, so a misaligned
    ///      recipient array can never send an NFT to the wrong address.
    struct TransferLeg {
        address assetContract;
        uint256 tokenId;
        uint256 quantity;
    }

    /// @notice One stored-listing fill in a `batchBuyListings` call.
    /// @dev `currency` and `maxTotalPrice` are the terms the buyer accepted when they built the
    ///      transaction. A stored listing is read live at execution and its seller can change its
    ///      price and currency with `updateListing` at any moment, so without them a buy would
    ///      settle at whatever terms happened to be in storage when it landed.
    struct BuyLeg {
        uint256 listingId;
        uint256 quantity;
        address currency;
        uint256 maxTotalPrice;
    }

    /// @notice What the chain remembers about one signed order.
    /// @dev Keyed by `keccak256(signer, orderHash)`, so a caller can only ever write their own
    ///      record and no signature has to be re-verified to cancel. The two fields share one slot
    ///      because the fill path reads them together.
    struct SignedOrderStatus {
        bool cancelled;
        uint248 filled;
    }

    // ============ Events ============

    event ListingCreated(
        uint256 indexed listingId,
        address indexed seller,
        address indexed assetContract,
        uint256 tokenId,
        uint256 quantity,
        address currency,
        uint256 pricePerToken,
        uint128 expiration,
        TokenType tokenType
    );

    event ListingUpdated(uint256 indexed listingId, address indexed seller, ListingUpdate params);
    event ListingCancelled(uint256 indexed listingId, address indexed seller);
    event StaleListingCancelled(uint256 indexed listingId, address indexed seller, address indexed cancelledBy);
    event StaleOfferCancelled(uint256 indexed offerId, address indexed offeror, address indexed cancelledBy);

    event Sale(
        uint256 indexed listingId,
        address indexed seller,
        address indexed buyer,
        address assetContract,
        uint256 tokenId,
        uint256 quantity,
        uint256 totalPrice,
        address currency,
        uint256 platformFeeAmount,
        uint256 royaltyAmount,
        address royaltyRecipient
    );

    event OfferCreated(
        uint256 indexed offerId,
        address indexed offeror,
        address indexed assetContract,
        uint256 tokenId,
        uint256 quantity,
        address currency,
        uint256 totalPrice,
        uint128 expirationTimestamp,
        TokenType tokenType
    );

    event OfferCancelled(uint256 indexed offerId, address indexed offeror);

    event OfferAccepted(
        uint256 indexed offerId,
        address indexed seller,
        address indexed buyer,
        address assetContract,
        uint256 tokenId,
        uint256 quantity,
        uint256 totalPrice,
        address currency,
        uint256 platformFeeAmount,
        uint256 royaltyAmount,
        address royaltyRecipient
    );

    event TokenTransferred(
        address indexed from,
        address indexed to,
        address indexed assetContract,
        uint256 tokenId,
        uint256 quantity,
        TokenType tokenType
    );

    /// @notice A signed listing was filled, in whole or in part.
    /// @dev `Sale` is keyed on a `listingId` a signed order does not have, so signed fills get
    ///      their own event keyed on the order hash. `filledToDate` is the cumulative quantity
    ///      filled against this order after this fill, which is what closes an ERC-1155 order.
    event SignedListingFilled(
        bytes32 indexed orderHash,
        address indexed seller,
        address indexed buyer,
        address assetContract,
        uint256 tokenId,
        uint256 quantity,
        uint256 filledToDate,
        uint256 totalPrice,
        address currency,
        uint256 platformFeeAmount,
        uint256 royaltyAmount,
        address royaltyRecipient
    );

    /// @notice A signed offer was accepted, in whole or in part.
    /// @dev `tokenId` and `quantity` are the leg's — the token the seller sold and the units it
    ///      took — since a criteria offer names its token only at acceptance. `filledToDate` is
    ///      the cumulative quantity filled against this order after this leg; the order is
    ///      exhausted when it reaches the signed quantity. `totalPrice` is this leg's
    ///      `pricePerToken * quantity`.
    event SignedOfferAccepted(
        bytes32 indexed orderHash,
        address indexed seller,
        address indexed buyer,
        address assetContract,
        uint256 tokenId,
        uint256 quantity,
        uint256 filledToDate,
        uint256 totalPrice,
        address currency,
        uint256 platformFeeAmount,
        uint256 royaltyAmount,
        address royaltyRecipient
    );

    event SignedOrdersCancelled(address indexed signer, bytes32[] orderHashes);
    event CounterIncremented(address indexed signer, uint256 newCounter);
    event PlatformSignerUpdated(address indexed signer, bool authorized);
    event MaxOrderDurationUpdated(uint64 maxOrderDuration);
    event CosignatureValidityUpdated(uint64 cosignatureValidity);

    event CollectionApprovalUpdated(address indexed collection, bool approved);

    /// @notice A curator pinned, changed or cleared which standard a collection is treated as
    ///         speaking. `tokenType` is `0` (auto-detect via ERC-165), `1` (ERC-721) or
    ///         `2` (ERC-1155).
    event CollectionTokenTypeUpdated(address indexed collection, uint8 tokenType);

    event CollectionPauseUpdated(address indexed collection, bool paused);
    event RoyaltyOverrideUpdated(address indexed collection, address recipient, uint16 feeBps, bool isSet);

    /// @notice A collection's creator switched the marketplace's unpaid transfer path on or off
    ///         for that collection.
    event CollectionTransfersUpdated(address indexed collection, bool disabled);
    event CurrencyApprovalUpdated(address indexed currency, bool approved);
    event PlatformFeeUpdated(address indexed recipient, uint16 feeBps);
    event NativeRescued(address indexed to, uint256 amount);

    // ============ Errors ============

    error CollectionNotApproved(address collection);
    error CollectionPaused(address collection);

    /// @notice No token standard resolved for this collection, so nothing here can move its
    ///         tokens.
    /// @dev Raised when the collection has no curator override and its ERC-165 answers claim
    ///      neither ERC-1155 nor ERC-721 — including a collection that behaves as one of the two
    ///      but misreports itself. A curator can pin the standard with `setCollectionTokenType`,
    ///      after which this no longer fires for that collection; `previewTokenType` reports the
    ///      same conclusion without reverting.
    error TokenTypeNotSupported(address collection);

    /// @notice `setCollectionTokenType` was called with a value that is not `0`, `1` or `2`.
    /// @param tokenType The rejected value.
    error InvalidTokenType(uint8 tokenType);

    error ListingNotActive(uint256 listingId);
    error ListingExpired(uint256 listingId);
    error NotListingSeller(uint256 listingId, address caller);
    error InvalidExpiration();
    error InvalidQuantity();

    /// @notice The stored listing no longer has the terms the buyer accepted: its currency is not
    ///         the one the buyer named, or its total for the requested quantity is above the
    ///         buyer's maximum.
    /// @dev Closes a front-run. A stored buy names only a listing id, and `updateListing` can
    ///      change the listing's price and currency at any moment, so a seller who saw a buy in
    ///      the mempool could raise the price ahead of it and the buyer would settle at terms they
    ///      never saw, bounded only by their ERC-20 allowance. Every buy now carries the currency
    ///      and the most it will pay, and settlement refuses anything else. A lower price is not
    ///      a changed term: the buy settles at the lower price.
    /// @param listingId The listing whose terms moved.
    /// @param currency The listing's currency as stored at execution.
    /// @param totalPrice The listing's total for the requested quantity as stored at execution.
    error ListingTermsChanged(uint256 listingId, address currency, uint256 totalPrice);

    error OfferNotActive(uint256 offerId);
    error OfferExpired(uint256 offerId);
    error NotOfferor(uint256 offerId, address caller);
    error OfferCurrencyMustBeERC20();
    error InvalidOfferExpiration();

    error CurrencyNotApproved(address currency);
    error InsufficientPayment(uint256 expected, uint256 actual);
    error NativeTransferFailed(address recipient, uint256 amount);

    error PlatformFeeTooHigh(uint16 feeBps);

    /// @notice The seller would net less than the minimum they committed to on this accept.
    /// @dev Raised by `acceptOffer` and `acceptSignedOffer` (and so by `batchAcceptSignedOffers`,
    ///      which reverts as a whole) after the platform fee and the royalty have been resolved
    ///      and clamped, and before any payment moves. A royalty override or platform fee that
    ///      rose between the seller quoting their proceeds and the accept landing surfaces here,
    ///      with what the seller would actually have netted, rather than as a silently smaller
    ///      payout. A `minSellerProceeds` of zero never triggers it.
    /// @param proceeds What the seller would have received: `totalPrice - platformFee - royalty`.
    /// @param minimum The `minSellerProceeds` the seller passed.
    error SellerProceedsBelowMinimum(uint256 proceeds, uint256 minimum);

    /// @notice Thrown by `setRoyaltyOverride` when the override exceeds the royalty ceiling.
    /// @dev The ceiling is the platform fee's complement, `10000 - platformFeeBps` bps: a seller
    ///      may give away everything the platform fee leaves and net zero, but no more. Checked
    ///      when the override is set, against the platform fee in force at that moment.
    /// @param feeBps The rejected override, in basis points.
    error RoyaltyOverrideTooHigh(uint16 feeBps);

    /// @notice Defensive guard on the settlement invariant `platformFee + royalty <= price`.
    /// @dev Unreachable in practice: settlement clamps the royalty to `price - platformFeeAmount`.
    error TotalFeesExceedPrice(uint256 totalFees, uint256 price);
    error ZeroPriceNotAllowed();

    error ZeroAddress();
    error CallerNotOwner(uint256 tokenId, address caller);
    error InsufficientTokenBalance(address owner, uint256 tokenId, uint256 required, uint256 actual);
    error MarketplaceNotApproved(address owner, address collection);
    error ListingNotStale(uint256 listingId);
    error OfferNotStale(uint256 offerId);
    error CannotBuyOwnListing(uint256 listingId);
    error CannotAcceptOwnOffer(uint256 offerId);
    error CannotTransferToSelf();
    error BatchTooLarge(uint256 length, uint256 max);

    /// @notice The caller may not change this collection's settings: not its `owner()`, not a
    ///         holder of its default admin role, and not the curator of an ownerless collection.
    error NotCollectionManager(address collection, address caller);

    /// @notice The collection's creator has switched off unpaid transfers through the marketplace.
    error CollectionTransfersDisabled(address collection);

    // ============ Signed Order Errors ============

    /// @notice The maker's signature does not cover this order, under this domain, for this signer.
    error InvalidOrderSignature();

    /// @notice The co-signature recovered to an address that is not a registered platform signer.
    error UnauthorizedCosigner(address recovered);

    error CosignatureExpired(uint64 expiry);

    /// @notice The attestation outlives `cosignatureValidity`, so no signer may mint it.
    error CosignatureValidityExceeded(uint64 expiry, uint256 maxExpiry);

    /// @notice The attestation names a different buyer than the caller.
    error CosignatureFulfillerMismatch(address fulfiller, address caller);

    error CounterMismatch(uint256 orderCounter, uint256 currentCounter);
    error OrderCancelled(bytes32 orderHash);
    error OrderExpired(bytes32 orderHash);

    /// @notice The order outlives `maxOrderDuration`, the trustless backstop on order lifetime.
    error OrderDurationTooLong(uint256 expiration, uint256 maxExpiration);

    /// @notice The requested quantity is more than this order has left to give.
    error OrderQuantityExceeded(bytes32 orderHash, uint256 requested, uint256 remaining);

    /// @notice The signed fee is above `MAX_PLATFORM_FEE_BPS`, the only bound settlement puts on it.
    error OrderFeeTooHigh(uint256 feeBps);

    error CannotFillOwnOrder(bytes32 orderHash);

    /// @notice The token the seller offered is not one this signed offer covers: it is not the
    ///         order's exact `tokenId`, or its Merkle proof does not reach the order's criteria root.
    error OfferTokenNotEligible(bytes32 orderHash, uint256 tokenId);

    /// @notice A criteria offer (nonzero `criteriaRoot`) was signed with a nonzero `tokenId`.
    /// @dev The field is ignored on the criteria path, so a nonzero value is a malformed order —
    ///      most likely a site that reused an exact-offer form — and what a wallet rendered as
    ///      "token 7" would have settled against any id under the root. Refused outright rather
    ///      than silently ignored. An exact-token offer on id 0 (zero root) is unaffected.
    error CriteriaOfferNamesToken(bytes32 orderHash);

    error MaxOrderDurationTooLong(uint64 duration, uint64 limit);
    error CosignatureValidityTooLong(uint64 validity, uint64 limit);

    /// @notice `setMaxOrderDuration` was called with less than `MIN_ORDER_DURATION`.
    /// @dev At zero no signed order can ever satisfy the lifetime cap, which would stop every
    ///      signed fill without anything looking paused. The floor keeps the admin's only visible
    ///      stop the pause itself.
    error MaxOrderDurationTooShort(uint64 duration, uint64 minimum);

    /// @notice `setCosignatureValidity` was called with less than `MIN_COSIGNATURE_VALIDITY`.
    /// @dev At zero no attestation can be both unexpired and within the window, which would stop
    ///      every signed fill without anything looking paused. Same rationale as
    ///      `MaxOrderDurationTooShort`.
    error CosignatureValidityTooShort(uint64 validity, uint64 minimum);

    // ============ Transfer Functions ============

    function transferToken(address assetContract, uint256 tokenId, uint256 quantity, address to) external;
    function batchTransferTokens(TransferLeg[] calldata legs, address to) external;

    // ============ Listing Functions ============

    function createListing(ListingParameters calldata params) external returns (uint256 listingId);
    function buyListing(uint256 listingId, uint256 quantity, address currency, uint256 maxTotalPrice) external payable;
    function batchBuyListings(BuyLeg[] calldata legs) external payable;
    function cancelListing(uint256 listingId) external;
    function cancelStaleListing(uint256 listingId) external;
    function updateListing(uint256 listingId, ListingUpdate calldata params) external;

    // ============ Offer Functions ============

    function makeOffer(OfferParameters calldata params) external returns (uint256 offerId);

    /// @notice Accepts a stored offer, settling it whole.
    /// @param offerId The stored offer.
    /// @param minSellerProceeds The least the caller will accept after the platform fee and the
    ///        royalty, in the offer's currency; the accept reverts `SellerProceedsBelowMinimum`
    ///        below it. Pass zero to accept whatever the live royalty and fee leave.
    function acceptOffer(uint256 offerId, uint256 minSellerProceeds) external;
    function cancelOffer(uint256 offerId) external;
    function cancelStaleOffer(uint256 offerId) external;

    // ============ Signed Order Functions ============

    function fulfillSignedListing(
        SignedOrders.SignedListing calldata order,
        bytes calldata signature,
        uint256 quantity,
        SignedOrders.Cosignature calldata cosig
    ) external payable;

    function batchFulfillSignedListings(SignedOrders.SignedFill[] calldata fills) external payable;

    function acceptSignedOffer(SignedOrders.SignedOfferAccept calldata accept) external;
    function batchAcceptSignedOffers(SignedOrders.SignedOfferAccept[] calldata accepts) external;

    function cancelSignedOrders(bytes32[] calldata orderHashes) external;
    function incrementCounter() external returns (uint256 newCounter);

    // ============ Curation Functions ============

    function setCollectionApproval(address collection, bool approved) external;
    function setCurrencyApproval(address currency, bool approved) external;
    function setCollectionPaused(address collection, bool paused) external;

    /// @notice Pins which standard the marketplace treats `collection` as speaking: `1` ERC-721,
    ///         `2` ERC-1155, `0` to restore ERC-165 auto-detect. Curator only; settable for any
    ///         collection, approved or not. Reverts `InvalidTokenType` above `2`.
    function setCollectionTokenType(address collection, uint8 tokenType) external;

    // ============ Collection Settings (creator) ============

    /// @notice Sets or clears a collection's royalty override. Callable by the collection's
    ///         manager (see `isCollectionManager`), never by the marketplace's admin.
    function setRoyaltyOverride(address collection, address recipient, uint16 feeBps, bool isSet) external;

    /// @notice Switches the marketplace's unpaid transfer path off or on for a collection.
    ///         Sales are unaffected. Same authority as `setRoyaltyOverride`.
    function setTransfersDisabled(address collection, bool disabled) external;

    // ============ Admin Functions ============

    function setPlatformFee(address recipient, uint16 feeBps) external;
    function setPlatformSigner(address signer, bool authorized) external;
    function setMaxOrderDuration(uint64 duration) external;
    function setCosignatureValidity(uint64 validity) external;
    function pause() external;
    function unpause() external;

    // ============ Rescue Functions ============

    function rescueERC20(address token, address to, uint256 amount) external;
    function rescueERC721(address collection, address to, uint256 tokenId) external;
    function rescueERC1155(address collection, address to, uint256 tokenId, uint256 amount) external;
    function rescueNative(address to, uint256 amount) external;

    // ============ View Functions ============

    function getListing(uint256 listingId) external view returns (Listing memory);
    function getOffer(uint256 offerId) external view returns (Offer memory);
    function isCollectionApproved(address collection) external view returns (bool);
    function isCollectionPaused(address collection) external view returns (bool);
    function getRoyaltyOverride(address collection) external view returns (RoyaltyOverride memory);
    function isCurrencyApproved(address currency) external view returns (bool);

    /// @notice Whether the marketplace's unpaid transfer path is switched off for a collection.
    function areTransfersDisabled(address collection) external view returns (bool);

    /// @notice The raw token-type override stored for a collection: `0` auto-detect, `1` ERC-721,
    ///         `2` ERC-1155. Says where `previewTokenType`'s answer came from.
    function getCollectionTokenType(address collection) external view returns (uint8);

    /// @notice What the marketplace will conclude this collection's standard is — `1` ERC-721,
    ///         `2` ERC-1155, `0` when nothing resolves — using exactly the resolution every
    ///         trading path runs. Never reverts, for any address.
    function previewTokenType(address collection) external view returns (uint8);

    /// @notice Whether `account` may change `collection`'s settings here: the collection's
    ///         `owner()`, a holder of its default admin role, or — only when the collection has
    ///         no resolvable owner — a marketplace curator.
    /// @dev The role path is ignored for a collection whose `hasRole` grants the default admin
    ///      role to `address(0)`: such a collection answers true for everyone, so only its
    ///      `owner()` counts. Both reads are gas-capped and bounded, so a hostile collection can
    ///      neither burn the caller's gas nor return-data-bomb the check.
    function isCollectionManager(address collection, address account) external view returns (bool);
    function getPlatformFeeInfo() external view returns (address recipient, uint16 bps);

    function getSignerCounter(address signer) external view returns (uint256);
    function getSignedOrderStatus(address signer, bytes32 orderHash) external view returns (SignedOrderStatus memory);
    function isPlatformSigner(address signer) external view returns (bool);
    function getMaxOrderDuration() external view returns (uint64);
    function getCosignatureValidity() external view returns (uint64);
    function bulkListingTypehash(uint256 height) external pure returns (bytes32);
    function bulkOfferTypehash(uint256 height) external pure returns (bytes32);
    function maxBulkOrderHeight() external pure returns (uint256);

    /// @notice The order hash of a signed listing: its EIP-712 struct hash, with no domain.
    /// @dev This is the identifier used everywhere an order is named — `SignedListingFilled`,
    ///      `cancelSignedOrders`, `getSignedOrderStatus`, and the `orderHash` a
    ///      `FulfillmentAuthorization` binds to. It is the same on every chain.
    function signedListingOrderHash(SignedOrders.SignedListing calldata order) external pure returns (bytes32);

    /// @notice The order hash of a signed offer: its EIP-712 struct hash, with no domain.
    function signedOfferOrderHash(SignedOrders.SignedOffer calldata order) external pure returns (bytes32);

    /// @notice The digest a seller signs for a signed listing: the order hash under this
    ///         deployment's EIP-712 domain, which is what the contract verifies the signature
    ///         against.
    function hashSignedListing(SignedOrders.SignedListing calldata order) external view returns (bytes32);

    /// @notice The digest an offeror signs for a signed offer.
    function hashSignedOffer(SignedOrders.SignedOffer calldata order) external view returns (bytes32);

    /// @notice The digest a platform signer signs to authorize one fill of one order.
    function hashFulfillmentAuthorization(bytes32 orderHash, address fulfiller, uint256 expiry)
        external
        view
        returns (bytes32);
}
