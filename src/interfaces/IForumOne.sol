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

    /// @notice A signed offer was accepted. Signed offers settle whole, so `filledToDate` always
    ///         equals the order's quantity.
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
    event CollectionPauseUpdated(address indexed collection, bool paused);
    event RoyaltyOverrideUpdated(address indexed collection, address recipient, uint16 feeBps, bool isSet);
    event CurrencyApprovalUpdated(address indexed currency, bool approved);
    event PlatformFeeUpdated(address indexed recipient, uint16 feeBps);
    event NativeRescued(address indexed to, uint256 amount);

    // ============ Errors ============

    error CollectionNotApproved(address collection);
    error CollectionPaused(address collection);
    error TokenTypeNotSupported(address collection);

    error ListingNotActive(uint256 listingId);
    error ListingExpired(uint256 listingId);
    error NotListingSeller(uint256 listingId, address caller);
    error InvalidExpiration();
    error InvalidQuantity();

    error OfferNotActive(uint256 offerId);
    error OfferExpired(uint256 offerId);
    error NotOfferor(uint256 offerId, address caller);
    error OfferCurrencyMustBeERC20();
    error InvalidOfferExpiration();

    error CurrencyNotApproved(address currency);
    error InsufficientPayment(uint256 expected, uint256 actual);
    error NativeTransferFailed(address recipient, uint256 amount);

    error PlatformFeeTooHigh(uint16 feeBps);

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
    error ArrayLengthMismatch();
    error ListingNotStale(uint256 listingId);
    error OfferNotStale(uint256 offerId);
    error CannotBuyOwnListing(uint256 listingId);
    error CannotAcceptOwnOffer(uint256 offerId);
    error CannotTransferToSelf();
    error BatchTooLarge(uint256 length, uint256 max);

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

    error MaxOrderDurationTooLong(uint64 duration, uint64 limit);
    error CosignatureValidityTooLong(uint64 validity, uint64 limit);

    // ============ Transfer Functions ============

    function transferToken(address assetContract, uint256 tokenId, uint256 quantity, address to) external;
    function batchTransferTokens(TransferLeg[] calldata legs, address to) external;

    // ============ Listing Functions ============

    function createListing(ListingParameters calldata params) external returns (uint256 listingId);
    function buyListing(uint256 listingId, uint256 quantity) external payable;
    function batchBuyListings(uint256[] calldata listingIds, uint256[] calldata quantities) external payable;
    function cancelListing(uint256 listingId) external;
    function cancelStaleListing(uint256 listingId) external;
    function updateListing(uint256 listingId, ListingUpdate calldata params) external;

    // ============ Offer Functions ============

    function makeOffer(OfferParameters calldata params) external returns (uint256 offerId);
    function acceptOffer(uint256 offerId) external;
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

    function acceptSignedOffer(
        SignedOrders.SignedOffer calldata order,
        bytes calldata signature,
        SignedOrders.Cosignature calldata cosig
    ) external;

    function cancelSignedOrders(bytes32[] calldata orderHashes) external;
    function incrementCounter() external returns (uint256 newCounter);

    // ============ Curation Functions ============

    function setCollectionApproval(address collection, bool approved) external;
    function setRoyaltyOverride(address collection, address recipient, uint16 feeBps, bool isSet) external;
    function setCurrencyApproval(address currency, bool approved) external;
    function setCollectionPaused(address collection, bool paused) external;

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
