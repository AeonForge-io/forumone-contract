// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {EIP712Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";
import {SafeCast} from "@openzeppelin/contracts/utils/math/SafeCast.sol";
import {IERC721} from "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import {IERC1155} from "@openzeppelin/contracts/token/ERC1155/IERC1155.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

import {IForumOne} from "./interfaces/IForumOne.sol";
import {SignedOrders} from "./libraries/SignedOrders.sol";
import {MarketplaceStorage, MarketplaceStorageLib} from "./libraries/MarketplaceStorage.sol";
import {ForumOneSettlement, Settlement} from "./libraries/ForumOneSettlement.sol";
import {ForumOneOrders} from "./libraries/ForumOneOrders.sol";
import {SignedOrderChecks} from "./libraries/SignedOrderChecks.sol";

contract ForumOne is
    Initializable,
    AccessControlUpgradeable,
    ReentrancyGuardTransient,
    PausableUpgradeable,
    EIP712Upgradeable,
    UUPSUpgradeable,
    IForumOne
{
    using SafeERC20 for IERC20;
    using SignedOrders for SignedOrders.SignedListing;
    using SignedOrders for SignedOrders.SignedOffer;

    bytes32 public constant CURATOR_ROLE = keccak256("CURATOR_ROLE");

    /// @dev Aliased from `SignedOrders` so this contract and `SignedOrderChecks` enforce the same
    ///      ceiling and can never disagree.
    uint16 public constant MAX_PLATFORM_FEE_BPS = SignedOrders.MAX_PLATFORM_FEE_BPS;
    uint256 private constant BPS_DENOMINATOR = 10_000;
    uint256 public constant MAX_BATCH_SIZE = 50;

    /// @notice The hard ceiling on `maxOrderDuration`, so no admin call can make outstanding
    ///         signed orders effectively permanent.
    uint64 public constant MAX_ORDER_DURATION_LIMIT = 180 days;

    /// @notice The hard ceiling on `cosignatureValidity`, so no platform signer can mint a
    ///         long-lived attestation.
    uint64 public constant MAX_COSIGNATURE_VALIDITY = 1 hours;

    /// @notice The floor on `maxOrderDuration`. At zero no signed order could satisfy the
    ///         lifetime cap and every signed fill would stop with nothing looking paused; the
    ///         pause is meant to be the one visible stop.
    uint64 public constant MIN_ORDER_DURATION = 1 days;

    /// @notice The floor on `cosignatureValidity`. At zero no attestation could be both unexpired
    ///         and within the window, with the same silent effect as a zero order duration.
    uint64 public constant MIN_COSIGNATURE_VALIDITY = 60 seconds;

    /// @dev The EIP-712 signing domain. Deployments on different chains share one CREATE2 address,
    ///      so `chainId`, not `verifyingContract`, is what stops cross-chain signature replay.
    ///      Bumping the version invalidates every outstanding signed order at once.
    string private constant EIP712_NAME = "ForumOne";
    string private constant EIP712_VERSION = "1";

    uint64 private constant INITIAL_MAX_ORDER_DURATION = 180 days;
    uint64 private constant INITIAL_COSIGNATURE_VALIDITY = 300 seconds;

    // ============ ERC-7201 Namespaced Storage ============

    /// @dev The struct and its ERC-7201 base slot live in `libraries/MarketplaceStorage.sol` so
    ///      the external libraries can take a pointer to the same storage.
    function _getStorage() private pure returns (MarketplaceStorage storage $) {
        return MarketplaceStorageLib.layout();
    }

    // ============ Constructor ============

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    // ============ Initializer ============

    function initialize(address admin, address platformFeeRecipient, uint16 platformFeeBps) external initializer {
        if (admin == address(0) || platformFeeRecipient == address(0)) revert ZeroAddress();
        if (platformFeeBps > MAX_PLATFORM_FEE_BPS) revert PlatformFeeTooHigh(platformFeeBps);

        __AccessControl_init();
        __Pausable_init();
        __EIP712_init(EIP712_NAME, EIP712_VERSION);

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(CURATOR_ROLE, admin);

        MarketplaceStorage storage s = _getStorage();
        s.platformFeeRecipient = platformFeeRecipient;
        s.platformFeeBps = platformFeeBps;
        s.maxOrderDuration = INITIAL_MAX_ORDER_DURATION;
        s.cosignatureValidity = INITIAL_COSIGNATURE_VALIDITY;
    }

    // ============ ERC-165 ============

    function supportsInterface(bytes4 interfaceId) public view override(AccessControlUpgradeable) returns (bool) {
        return interfaceId == type(IForumOne).interfaceId || super.supportsInterface(interfaceId);
    }

    // ============ Admin Functions ============

    function setPlatformFee(address recipient, uint16 feeBps) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (recipient == address(0)) revert ZeroAddress();
        if (feeBps > MAX_PLATFORM_FEE_BPS) revert PlatformFeeTooHigh(feeBps);

        MarketplaceStorage storage s = _getStorage();
        s.platformFeeRecipient = recipient;
        s.platformFeeBps = feeBps;

        emit PlatformFeeUpdated(recipient, feeBps);
    }

    /// @notice Authorizes or revokes a platform co-signing key.
    /// @dev Admin-only, never curator: curation decides what may trade, this decides what may be
    ///      attested. Rotation is zero-downtime — authorize the new key, wait one validity window,
    ///      revoke the old one.
    function setPlatformSigner(address signer, bool authorized) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (signer == address(0)) revert ZeroAddress();

        _getStorage().platformSigners[signer] = authorized;

        emit PlatformSignerUpdated(signer, authorized);
    }

    /// @notice Sets how far into the future a signed order's expiration may reach.
    /// @dev Capped at `MAX_ORDER_DURATION_LIMIT` so no admin call can make outstanding signed
    ///      orders effectively permanent, and floored at `MIN_ORDER_DURATION` so none can stop
    ///      every signed fill without pausing.
    function setMaxOrderDuration(uint64 duration) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (duration > MAX_ORDER_DURATION_LIMIT) revert MaxOrderDurationTooLong(duration, MAX_ORDER_DURATION_LIMIT);
        if (duration < MIN_ORDER_DURATION) revert MaxOrderDurationTooShort(duration, MIN_ORDER_DURATION);

        _getStorage().maxOrderDuration = duration;

        emit MaxOrderDurationUpdated(duration);
    }

    /// @notice Sets how long a platform attestation may remain fillable.
    /// @dev Capped at `MAX_COSIGNATURE_VALIDITY` and floored at `MIN_COSIGNATURE_VALIDITY`. The
    ///      short window is what makes off-chain cancellation effective: an order becomes
    ///      unfillable within one window of the platform declining to attest it. The floor keeps
    ///      the window from being closed outright, which would stop every signed fill silently.
    function setCosignatureValidity(uint64 validity) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (validity > MAX_COSIGNATURE_VALIDITY) revert CosignatureValidityTooLong(validity, MAX_COSIGNATURE_VALIDITY);
        if (validity < MIN_COSIGNATURE_VALIDITY) {
            revert CosignatureValidityTooShort(validity, MIN_COSIGNATURE_VALIDITY);
        }

        _getStorage().cosignatureValidity = validity;

        emit CosignatureValidityUpdated(validity);
    }

    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    function _authorizeUpgrade(address) internal override onlyRole(DEFAULT_ADMIN_ROLE) {}

    // ============ Rescue Functions ============

    function rescueERC20(address token, address to, uint256 amount) external onlyRole(DEFAULT_ADMIN_ROLE) {
        IERC20(token).safeTransfer(to, amount);
    }

    function rescueERC721(address collection, address to, uint256 tokenId) external onlyRole(DEFAULT_ADMIN_ROLE) {
        IERC721(collection).safeTransferFrom(address(this), to, tokenId);
    }

    function rescueERC1155(address collection, address to, uint256 tokenId, uint256 amount)
        external
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        IERC1155(collection).safeTransferFrom(address(this), to, tokenId, amount, "");
    }

    function rescueNative(address to, uint256 amount) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (to == address(0)) revert ZeroAddress();
        emit NativeRescued(to, amount);
        (bool success,) = to.call{value: amount}("");
        if (!success) revert NativeTransferFailed(to, amount);
    }

    receive() external payable {}

    // ============ Curation Functions ============

    function setCollectionApproval(address collection, bool approved) external onlyRole(CURATOR_ROLE) {
        if (collection == address(0)) revert ZeroAddress();
        MarketplaceStorage storage s = _getStorage();
        s.approvedCollections[collection] = approved;
        emit CollectionApprovalUpdated(collection, approved);
    }

    function setCollectionPaused(address collection, bool paused_) external onlyRole(CURATOR_ROLE) {
        if (collection == address(0)) revert ZeroAddress();
        MarketplaceStorage storage s = _getStorage();
        s.pausedCollections[collection] = paused_;
        emit CollectionPauseUpdated(collection, paused_);
    }

    function setCurrencyApproval(address currency, bool approved) external onlyRole(CURATOR_ROLE) {
        if (currency == address(0)) revert ZeroAddress();
        MarketplaceStorage storage s = _getStorage();
        s.approvedCurrencies[currency] = approved;
        emit CurrencyApprovalUpdated(currency, approved);
    }

    /// @notice Pins which standard the marketplace treats a collection as speaking.
    /// @dev The answer to a collection that misreports itself through ERC-165. Detection asks the
    ///      collection `supportsInterface` for ERC-1155 and then ERC-721, and a contract that
    ///      behaves as one of the two but answers false for both — or answers for the other one —
    ///      cannot be traded or transferred here at all. This makes ERC-165 the default rather
    ///      than the authority: an override wins outright and the collection is not asked.
    ///
    ///      Curator, the role that decides what may trade here, and settable for any collection,
    ///      approved or not, so the pin can be in place before approval. `0` restores
    ///      auto-detect. Nothing is validated against the collection — a pin is a statement about
    ///      a contract the curator has read, and a wrong pin simply makes that collection's calls
    ///      fail the way the pinned standard's calls fail; `previewTokenType` is what the panel
    ///      checks it with beforehand.
    /// @param collection The collection to pin.
    /// @param tokenType `0` auto-detect, `1` ERC-721, `2` ERC-1155. Anything above reverts.
    function setCollectionTokenType(address collection, uint8 tokenType) external onlyRole(CURATOR_ROLE) {
        if (collection == address(0)) revert ZeroAddress();
        if (tokenType > MarketplaceStorageLib.TOKEN_TYPE_ERC1155) revert InvalidTokenType(tokenType);

        _getStorage().collectionTokenType[collection] = tokenType;
        emit CollectionTokenTypeUpdated(collection, tokenType);
    }

    // ============ Collection Settings (creator) ============
    //
    // These two belong to the collection's creator, not to the marketplace: its `owner()` or a
    // holder of its default admin role, the same rule a Limit Break transfer validator applies to
    // its own settings. The marketplace's admin has no standing here, and a curator only stands in
    // for a collection that has no resolvable owner (`ForumOneSettlement.isCollectionManager`).

    /// @notice Sets or clears a collection's royalty override.
    /// @dev An override may take up to `10000 - platformFeeBps` bps — everything the platform fee
    ///      does not, leaving the seller netting zero. Anything above that reverts with
    ///      `RoyaltyOverrideTooHigh`. The ceiling is checked against the fee in force at set time;
    ///      if the platform fee is raised afterwards the sale still settles, because settlement
    ///      clamps the royalty to `price - platformFeeAmount`. Overrides written before the v2
    ///      upgrade stay as they are until the creator replaces or clears them.
    function setRoyaltyOverride(address collection, address recipient, uint16 feeBps, bool isSet) external {
        if (collection == address(0)) revert ZeroAddress();
        if (isSet && recipient == address(0)) revert ZeroAddress();
        _requireCollectionManager(collection);

        MarketplaceStorage storage s = _getStorage();
        if (uint256(feeBps) + s.platformFeeBps > BPS_DENOMINATOR) revert RoyaltyOverrideTooHigh(feeBps);

        s.royaltyOverrides[collection] = RoyaltyOverride({recipient: recipient, feeBps: feeBps, isSet: isSet});
        emit RoyaltyOverrideUpdated(collection, recipient, feeBps, isSet);
    }

    /// @notice Switches the marketplace's unpaid transfer path — `transferToken` and
    ///         `batchTransferTokens` — off or on for a collection. Sales are never affected.
    /// @dev Exists so a collection whose own policy forbids free transfers can have the
    ///      marketplace honour that policy itself, rather than be that collection's one
    ///      royalty-free way to move a token.
    function setTransfersDisabled(address collection, bool disabled) external {
        if (collection == address(0)) revert ZeroAddress();
        _requireCollectionManager(collection);

        _getStorage().transfersDisabled[collection] = disabled;
        emit CollectionTransfersUpdated(collection, disabled);
    }

    function _requireCollectionManager(address collection) private view {
        if (!ForumOneSettlement.isCollectionManager(collection, msg.sender, hasRole(CURATOR_ROLE, msg.sender))) {
            revert NotCollectionManager(collection, msg.sender);
        }
    }

    // ============ Transfer Functions ============

    function transferToken(address assetContract, uint256 tokenId, uint256 quantity, address to)
        external
        whenNotPaused
    {
        if (to == address(0)) revert ZeroAddress();
        if (to == msg.sender) revert CannotTransferToSelf();

        ForumOneSettlement.transferLeg(_getStorage(), msg.sender, to, assetContract, tokenId, quantity);
    }

    /// @notice Moves several tokens, across several collections, to one recipient in one call.
    /// @dev Every leg runs `transferToken`'s checks and emits the same `TokenTransferred` event.
    ///      One failing leg reverts the whole batch. The `nonReentrant` guard is defensive:
    ///      re-entry could only move tokens the caller already owns and has approved, and the
    ///      guard is nearly free with transient storage.
    /// @param legs The tokens to move.
    /// @param to The single recipient of every leg.
    function batchTransferTokens(TransferLeg[] calldata legs, address to) external nonReentrant whenNotPaused {
        if (to == address(0)) revert ZeroAddress();
        if (to == msg.sender) revert CannotTransferToSelf();
        if (legs.length > MAX_BATCH_SIZE) revert BatchTooLarge(legs.length, MAX_BATCH_SIZE);

        ForumOneSettlement.batchTransfer(_getStorage(), msg.sender, to, legs);
    }

    // ============ Listing Functions ============

    function createListing(ListingParameters calldata params) external whenNotPaused returns (uint256 listingId) {
        return ForumOneOrders.createListing(_getStorage(), params);
    }

    /// @notice Fills a stored listing at terms the buyer chose.
    /// @dev The listing is read live, so the buyer names the currency and the most they will pay
    ///      and the fill reverts `ListingTermsChanged` if `updateListing` moved either underneath
    ///      them; a lower price settles at the lower price. A native fill requires
    ///      `msg.value >= total` as stored and the excess is refunded in the same transaction. The
    ///      native total is summed from storage before the terms check runs, so the msg.value
    ///      check cannot be relied on as a price bound — `maxTotalPrice` is.
    /// @param listingId The stored listing.
    /// @param quantity Units to take. An ERC-1155 listing may be filled in parts until exhausted.
    /// @param currency The currency the buyer accepted, `address(0)` for native.
    /// @param maxTotalPrice The most the buyer will pay for `quantity` units, in that currency.
    function buyListing(uint256 listingId, uint256 quantity, address currency, uint256 maxTotalPrice)
        external
        payable
        nonReentrant
        whenNotPaused
    {
        MarketplaceStorage storage s = _getStorage();
        Listing storage listing = s.listings[listingId];
        uint256 nativeRequired;
        if (listing.currency == address(0)) {
            nativeRequired = listing.pricePerToken * quantity;
            if (msg.value < nativeRequired) revert InsufficientPayment(nativeRequired, msg.value);
        }

        _executeBuy(listingId, quantity, currency, maxTotalPrice);

        if (msg.value > nativeRequired) {
            uint256 refund = msg.value - nativeRequired;
            (bool success,) = msg.sender.call{value: refund}("");
            if (!success) revert NativeTransferFailed(msg.sender, refund);
        }
    }

    /// @notice Fills several stored listings in one all-or-nothing call.
    /// @dev Each leg carries the terms its buyer accepted and is checked as `buyListing` checks
    ///      one; a single leg whose terms moved reverts the whole batch. The native total is
    ///      summed from storage and the excess refunded once at the end.
    /// @param legs The fills, at most `MAX_BATCH_SIZE`.
    function batchBuyListings(BuyLeg[] calldata legs) external payable nonReentrant whenNotPaused {
        if (legs.length > MAX_BATCH_SIZE) revert BatchTooLarge(legs.length, MAX_BATCH_SIZE);

        MarketplaceStorage storage s = _getStorage();
        uint256 totalNativeRequired;
        for (uint256 i = 0; i < legs.length;) {
            Listing storage listing = s.listings[legs[i].listingId];
            if (listing.currency == address(0)) {
                totalNativeRequired += listing.pricePerToken * legs[i].quantity;
            }
            unchecked {
                ++i;
            }
        }
        if (msg.value < totalNativeRequired) revert InsufficientPayment(totalNativeRequired, msg.value);

        for (uint256 i = 0; i < legs.length;) {
            _executeBuy(legs[i].listingId, legs[i].quantity, legs[i].currency, legs[i].maxTotalPrice);
            unchecked {
                ++i;
            }
        }

        if (msg.value > totalNativeRequired) {
            uint256 refund = msg.value - totalNativeRequired;
            (bool success,) = msg.sender.call{value: refund}("");
            if (!success) revert NativeTransferFailed(msg.sender, refund);
        }
    }

    function cancelListing(uint256 listingId) external {
        ForumOneOrders.cancelListing(_getStorage(), listingId);
    }

    /// @notice Cancels a listing whose seller no longer holds the listed token.
    function cancelStaleListing(uint256 listingId) external nonReentrant onlyRole(CURATOR_ROLE) {
        ForumOneOrders.cancelStaleListing(_getStorage(), listingId);
    }

    /// @notice Changes a stored listing's currency, price and expiration at once, and re-fixes
    ///         the royalty and platform fee it will settle under.
    /// @dev `nonReentrant` so a seller contract paid mid-batch cannot re-enter here and move a
    ///      later leg's terms underneath the same buyer; `cancelListing` stays unguarded, since
    ///      cancelling can only make a later leg revert.
    function updateListing(uint256 listingId, ListingUpdate calldata params) external nonReentrant whenNotPaused {
        ForumOneOrders.updateListing(_getStorage(), listingId, params);
    }

    // ============ Offer Functions ============

    function makeOffer(OfferParameters calldata params) external whenNotPaused returns (uint256 offerId) {
        return ForumOneOrders.makeOffer(_getStorage(), params);
    }

    /// @notice Accepts a stored offer, settling it whole.
    /// @dev A stored offer resolves its royalty and fee live at acceptance, so the seller names
    ///      the least they will net; a royalty raised since they quoted it makes the accept
    ///      revert `SellerProceedsBelowMinimum` rather than pay them less.
    function acceptOffer(uint256 offerId, uint256 minSellerProceeds) external nonReentrant whenNotPaused {
        ForumOneOrders.acceptOffer(_getStorage(), offerId, minSellerProceeds);
    }

    function cancelOffer(uint256 offerId) external {
        ForumOneOrders.cancelOffer(_getStorage(), offerId);
    }

    /// @notice Cancels an offer the offeror can no longer honor.
    function cancelStaleOffer(uint256 offerId) external nonReentrant onlyRole(CURATOR_ROLE) {
        ForumOneOrders.cancelStaleOffer(_getStorage(), offerId);
    }

    // ============ Signed Order Functions ============

    /// @notice Fills a listing the seller signed rather than stored.
    /// @dev Payment mirrors `buyListing`: a native fill requires `msg.value >= total` and the
    ///      excess is refunded in the same transaction; an ERC-20 fill moves the currency straight
    ///      from buyer to recipients, so the contract custodies nothing.
    /// @param order The signed listing.
    /// @param signature The maker's signature over the order, EOA or ERC-1271.
    /// @param quantity Units to take. An ERC-1155 order may be filled in parts until exhausted.
    /// @param cosig The platform's attestation that this fill is authorized, now, for this caller.
    function fulfillSignedListing(
        SignedOrders.SignedListing calldata order,
        bytes calldata signature,
        uint256 quantity,
        SignedOrders.Cosignature calldata cosig
    ) external payable nonReentrant whenNotPaused {
        uint256 nativeRequired;
        if (order.currency == address(0)) {
            nativeRequired = order.pricePerToken * quantity;
            if (msg.value < nativeRequired) revert InsufficientPayment(nativeRequired, msg.value);
        }

        _fulfillSignedListing(order, signature, quantity, cosig);

        if (msg.value > nativeRequired) {
            uint256 refund = msg.value - nativeRequired;
            (bool success,) = msg.sender.call{value: refund}("");
            if (!success) revert NativeTransferFailed(msg.sender, refund);
        }
    }

    /// @notice Fills several signed listings in one all-or-nothing call.
    /// @dev Signed orders only; stored listings go through `batchBuyListings`. The native total is
    ///      summed from calldata and the excess refunded once at the end. Each leg carries its own
    ///      attestation.
    function batchFulfillSignedListings(SignedOrders.SignedFill[] calldata fills)
        external
        payable
        nonReentrant
        whenNotPaused
    {
        if (fills.length > MAX_BATCH_SIZE) revert BatchTooLarge(fills.length, MAX_BATCH_SIZE);

        uint256 totalNativeRequired;
        for (uint256 i = 0; i < fills.length;) {
            if (fills[i].order.currency == address(0)) {
                totalNativeRequired += fills[i].order.pricePerToken * fills[i].quantity;
            }
            unchecked {
                ++i;
            }
        }
        if (msg.value < totalNativeRequired) revert InsufficientPayment(totalNativeRequired, msg.value);

        for (uint256 i = 0; i < fills.length;) {
            _fulfillSignedListing(fills[i].order, fills[i].signature, fills[i].quantity, fills[i].cosig);
            unchecked {
                ++i;
            }
        }

        if (msg.value > totalNativeRequired) {
            uint256 refund = msg.value - totalNativeRequired;
            (bool success,) = msg.sender.call{value: refund}("");
            if (!success) revert NativeTransferFailed(msg.sender, refund);
        }
    }

    /// @notice Accepts a bid the offeror signed rather than stored, in whole or in part.
    /// @dev The caller is the seller: they hold `accept.tokenId`, sell `accept.quantity` units of
    ///      it, and are paid `pricePerToken * quantity` in the order's ERC-20, less the fee and
    ///      the royalty resolved live — so `accept.minSellerProceeds` is their floor on the net.
    ///      The offer stays open to other holders until its signed quantity is exhausted.
    function acceptSignedOffer(SignedOrders.SignedOfferAccept calldata accept) external nonReentrant whenNotPaused {
        _acceptSignedOffer(accept);
    }

    /// @notice Accepts several signed offers in one all-or-nothing call.
    /// @dev The legs may come from different offerors; each carries its own attestation, and the
    ///      caller is the seller of every one. One failing leg reverts the whole call.
    function batchAcceptSignedOffers(SignedOrders.SignedOfferAccept[] calldata accepts)
        external
        nonReentrant
        whenNotPaused
    {
        if (accepts.length > MAX_BATCH_SIZE) revert BatchTooLarge(accepts.length, MAX_BATCH_SIZE);

        for (uint256 i = 0; i < accepts.length;) {
            _acceptSignedOffer(accepts[i]);
            unchecked {
                ++i;
            }
        }
    }

    /// @notice Marks signed orders cancelled for the caller, without the platform's cooperation.
    /// @dev The everyday cancel is off chain — the platform stops attesting the hash — so this is
    ///      the trustless escape hatch. Records are keyed by `keccak256(msg.sender, orderHash)`,
    ///      so a caller can only cancel their own orders and no signature has to be re-verified.
    ///      Deliberately not `whenNotPaused` or `nonReentrant`: cancellation must survive a pause,
    ///      and this touches nothing but the caller's own records.
    function cancelSignedOrders(bytes32[] calldata orderHashes) external {
        MarketplaceStorage storage s = _getStorage();

        for (uint256 i = 0; i < orderHashes.length;) {
            s.signedOrderStatus[SignedOrders.statusKey(msg.sender, orderHashes[i])].cancelled = true;
            unchecked {
                ++i;
            }
        }

        emit SignedOrdersCancelled(msg.sender, orderHashes);
    }

    /// @notice Invalidates every outstanding signed order of the caller in one transaction.
    /// @dev Every order pins the counter it was signed under, so one bump kills the whole book.
    function incrementCounter() external returns (uint256 newCounter) {
        MarketplaceStorage storage s = _getStorage();

        unchecked {
            newCounter = ++s.signerCounter[msg.sender];
        }

        emit CounterIncremented(msg.sender, newCounter);
    }

    // ============ Internal: Signed Order Fulfilment ============

    /// @dev Verification order: maker signature first, so every later revert concerns a genuine
    ///      order; then the platform attestation; then counter and status; then expiry and the
    ///      lifetime cap; then the signed fee; then the same allowlist and quantity rules a stored
    ///      listing obeys; then ownership, approval and settlement. The fill count is written
    ///      before any external call, so a receiver hook that re-enters cannot over-fill the
    ///      order. No `msg.value` check here: the entry point that collects the native total
    ///      does it, as with `_executeBuy`.
    function _fulfillSignedListing(
        SignedOrders.SignedListing calldata order,
        bytes calldata signature,
        uint256 quantity,
        SignedOrders.Cosignature calldata cosig
    ) internal {
        (bytes32 orderHash, uint256 filledToDate) = SignedOrderChecks.checkSignedListing(
            _getStorage(), _domainSeparatorV4(), order, signature, quantity, cosig
        );

        TokenType tokenType = _detectTokenType(_getStorage(), order.assetContract);
        if (tokenType == TokenType.ERC721 && order.quantity != 1) revert InvalidQuantity();

        _settleSignedListing(order, quantity, tokenType, orderHash, filledToDate);
    }

    /// @dev Split out to keep the fill path's stack shallow; every check has already passed by
    ///      the time this runs.
    function _settleSignedListing(
        SignedOrders.SignedListing calldata order,
        uint256 quantity,
        TokenType tokenType,
        bytes32 orderHash,
        uint256 filledToDate
    ) private {
        uint256 totalPrice = order.pricePerToken * quantity;

        Settlement memory settlement;
        settlement.seller = order.signer;
        settlement.buyer = msg.sender;
        settlement.assetContract = order.assetContract;
        settlement.tokenId = order.tokenId;
        settlement.quantity = quantity;
        settlement.tokenType = tokenType;
        settlement.currency = order.currency;
        settlement.totalPrice = totalPrice;
        settlement.platformFeeBps = SafeCast.toUint16(order.platformFeeBps);

        SignedFillReceipt memory receipt;
        (receipt.royaltyRecipient, receipt.platformFeeAmount, receipt.royaltyAmount) = _settle(settlement);
        receipt.orderHash = orderHash;
        receipt.seller = order.signer;
        receipt.buyer = msg.sender;
        receipt.assetContract = order.assetContract;
        receipt.tokenId = order.tokenId;
        receipt.quantity = quantity;
        receipt.filledToDate = filledToDate;
        receipt.totalPrice = totalPrice;
        receipt.currency = order.currency;

        _emitSignedListingFilled(receipt);
    }

    /// @dev The offer counterpart of `_fulfillSignedListing`. Every check, including that the
    ///      leg's token is one the offer covers, runs in the library and writes the fill count
    ///      before any external call. ERC-721 fills one token per leg, and an offer on exactly
    ///      one ERC-721 token can only ever want one of it.
    function _acceptSignedOffer(SignedOrders.SignedOfferAccept calldata accept) private {
        (bytes32 orderHash, uint256 filledToDate) =
            SignedOrderChecks.checkSignedOffer(_getStorage(), _domainSeparatorV4(), accept);

        SignedOrders.SignedOffer calldata order = accept.order;
        TokenType tokenType = _detectTokenType(_getStorage(), order.assetContract);
        if (tokenType == TokenType.ERC721) {
            if (accept.quantity != 1) revert InvalidQuantity();
            if (order.criteriaRoot == bytes32(0) && order.quantity != 1) revert InvalidQuantity();
        }

        _settleSignedOffer(accept, tokenType, orderHash, filledToDate);
    }

    /// @dev The offer counterpart of `_settleSignedListing`: the leg's token and quantity, priced
    ///      per unit.
    function _settleSignedOffer(
        SignedOrders.SignedOfferAccept calldata accept,
        TokenType tokenType,
        bytes32 orderHash,
        uint256 filledToDate
    ) private {
        SignedOrders.SignedOffer calldata order = accept.order;
        uint256 totalPrice = order.pricePerToken * accept.quantity;

        Settlement memory settlement;
        settlement.seller = msg.sender;
        settlement.buyer = order.signer;
        settlement.assetContract = order.assetContract;
        settlement.tokenId = accept.tokenId;
        settlement.quantity = accept.quantity;
        settlement.tokenType = tokenType;
        settlement.currency = order.currency;
        settlement.totalPrice = totalPrice;
        settlement.platformFeeBps = SafeCast.toUint16(order.platformFeeBps);
        settlement.minSellerProceeds = accept.minSellerProceeds;

        SignedFillReceipt memory receipt;
        (receipt.royaltyRecipient, receipt.platformFeeAmount, receipt.royaltyAmount) = _settle(settlement);
        receipt.orderHash = orderHash;
        receipt.seller = msg.sender;
        receipt.buyer = order.signer;
        receipt.assetContract = order.assetContract;
        receipt.tokenId = accept.tokenId;
        receipt.quantity = accept.quantity;
        receipt.filledToDate = filledToDate;
        receipt.totalPrice = totalPrice;
        receipt.currency = order.currency;

        _emitSignedOfferAccepted(receipt);
    }

    function _emitSignedListingFilled(SignedFillReceipt memory receipt) private {
        emit SignedListingFilled(
            receipt.orderHash,
            receipt.seller,
            receipt.buyer,
            receipt.assetContract,
            receipt.tokenId,
            receipt.quantity,
            receipt.filledToDate,
            receipt.totalPrice,
            receipt.currency,
            receipt.platformFeeAmount,
            receipt.royaltyAmount,
            receipt.royaltyRecipient
        );
    }

    function _emitSignedOfferAccepted(SignedFillReceipt memory receipt) private {
        emit SignedOfferAccepted(
            receipt.orderHash,
            receipt.seller,
            receipt.buyer,
            receipt.assetContract,
            receipt.tokenId,
            receipt.quantity,
            receipt.filledToDate,
            receipt.totalPrice,
            receipt.currency,
            receipt.platformFeeAmount,
            receipt.royaltyAmount,
            receipt.royaltyRecipient
        );
    }

    // ============ View Functions ============

    function getListing(uint256 listingId) external view returns (Listing memory listing) {
        listing = _getStorage().listings[listingId];
        if (listing.status == ListingStatus.ACTIVE && listing.expiration <= block.timestamp) {
            listing.status = ListingStatus.CANCELLED;
        }
    }

    function getOffer(uint256 offerId) external view returns (Offer memory offer) {
        offer = _getStorage().offers[offerId];
        if (offer.status == OfferStatus.ACTIVE && offer.expirationTimestamp <= block.timestamp) {
            offer.status = OfferStatus.CANCELLED;
        }
    }

    function isCollectionApproved(address collection) external view returns (bool) {
        return _getStorage().approvedCollections[collection];
    }

    function isCollectionPaused(address collection) external view returns (bool) {
        return _getStorage().pausedCollections[collection];
    }

    function getRoyaltyOverride(address collection) external view returns (RoyaltyOverride memory) {
        return _getStorage().royaltyOverrides[collection];
    }

    function areTransfersDisabled(address collection) external view returns (bool) {
        return _getStorage().transfersDisabled[collection];
    }

    /// @notice The raw override stored for a collection: `0` auto-detect, `1` ERC-721,
    ///         `2` ERC-1155.
    /// @dev Says whether a resolved standard came from a curator's pin or from the collection's
    ///      own ERC-165 answers; `previewTokenType` says what the standard is.
    function getCollectionTokenType(address collection) external view returns (uint8) {
        return _getStorage().collectionTokenType[collection];
    }

    /// @notice What the marketplace will conclude this collection's standard is: `1` ERC-721,
    ///         `2` ERC-1155, or `0` when nothing resolves.
    /// @dev The same resolution every trading path runs — the override first, then the ERC-165
    ///      probes — reported instead of reverted, so the curator panel can ask the marketplace
    ///      itself rather than replicate the probes client-side and drift from it. A `0` is
    ///      exactly the case where every path that moves a token reverts
    ///      `TokenTypeNotSupported`, and a curator's `setCollectionTokenType` is what fixes it.
    ///
    ///      Never reverts, for any address: an EOA, an address with no code, and a contract with
    ///      no `supportsInterface` at all all answer `0`.
    function previewTokenType(address collection) external view returns (uint8) {
        return ForumOneSettlement.previewTokenType(_getStorage(), collection);
    }

    function isCollectionManager(address collection, address account) external view returns (bool) {
        return ForumOneSettlement.isCollectionManager(collection, account, hasRole(CURATOR_ROLE, account));
    }

    function isCurrencyApproved(address currency) external view returns (bool) {
        return _getStorage().approvedCurrencies[currency];
    }

    function getPlatformFeeInfo() external view returns (address recipient, uint16 bps) {
        MarketplaceStorage storage s = _getStorage();
        return (s.platformFeeRecipient, s.platformFeeBps);
    }

    function getSignerCounter(address signer) external view returns (uint256) {
        return _getStorage().signerCounter[signer];
    }

    function getSignedOrderStatus(address signer, bytes32 orderHash) external view returns (SignedOrderStatus memory) {
        return _getStorage().signedOrderStatus[SignedOrders.statusKey(signer, orderHash)];
    }

    function isPlatformSigner(address signer) external view returns (bool) {
        return _getStorage().platformSigners[signer];
    }

    function getMaxOrderDuration() external view returns (uint64) {
        return _getStorage().maxOrderDuration;
    }

    function getCosignatureValidity() external view returns (uint64) {
        return _getStorage().cosignatureValidity;
    }

    /// @notice The order hash of a signed listing: its EIP-712 struct hash, with no domain.
    /// @dev The identifier used wherever an order is named — the `SignedListingFilled` key,
    ///      `cancelSignedOrders`, `getSignedOrderStatus`, and the hash an attestation binds to.
    ///      The same on every chain; it is the digest below that is chain-specific.
    function signedListingOrderHash(SignedOrders.SignedListing calldata order) external pure returns (bytes32) {
        return order.hash();
    }

    /// @notice The order hash of a signed offer: its EIP-712 struct hash, with no domain.
    function signedOfferOrderHash(SignedOrders.SignedOffer calldata order) external pure returns (bytes32) {
        return order.hash();
    }

    /// @notice The digest a seller signs for a signed listing, and the one this contract verifies.
    function hashSignedListing(SignedOrders.SignedListing calldata order) external view returns (bytes32) {
        return _hashTypedDataV4(order.hash());
    }

    /// @notice The digest an offeror signs for a signed offer.
    function hashSignedOffer(SignedOrders.SignedOffer calldata order) external view returns (bytes32) {
        return _hashTypedDataV4(order.hash());
    }

    /// @notice The digest a platform signer signs to authorize one fill of one order.
    function hashFulfillmentAuthorization(bytes32 orderHash, address fulfiller, uint256 expiry)
        external
        view
        returns (bytes32)
    {
        return _hashTypedDataV4(SignedOrders.hashFulfillmentAuthorization(orderHash, fulfiller, expiry));
    }

    /// @notice The EIP-712 type hash of the bulk listing wrapper for a tree of the given height.
    /// @dev Forwarded from `SignedOrderChecks` so tooling pointed at the proxy can confirm the
    ///      type string a wallet was shown is the one this contract will hash. The derivation
    ///      lives in the external library; these three are forwarding stubs.
    function bulkListingTypehash(uint256 height) external pure returns (bytes32) {
        return SignedOrderChecks.bulkListingTypehash(height);
    }

    /// @notice The EIP-712 type hash of the bulk offer wrapper for a tree of the given height.
    function bulkOfferTypehash(uint256 height) external pure returns (bytes32) {
        return SignedOrderChecks.bulkOfferTypehash(height);
    }

    /// @notice The deepest bulk tree a signature can carry a proof for.
    function maxBulkOrderHeight() external pure returns (uint256) {
        return SignedOrderChecks.maxBulkOrderHeight();
    }

    // ============ Internal: Buy Execution ============

    function _executeBuy(uint256 listingId, uint256 quantity, address currency, uint256 maxTotalPrice) internal {
        ForumOneOrders.executeBuy(_getStorage(), listingId, quantity, currency, maxTotalPrice);
    }

    // ============ Internal: Settlement ============

    /// @notice Everything a signed fill reports, gathered so emitting the event does not need a
    ///         dozen values on the stack at once.
    /// @dev `SignedListingFilled` and `SignedOfferAccepted` carry the same fields, so one struct
    ///      serves both.
    struct SignedFillReceipt {
        bytes32 orderHash;
        address seller;
        address buyer;
        address assetContract;
        uint256 tokenId;
        uint256 quantity;
        uint256 filledToDate;
        uint256 totalPrice;
        address currency;
        uint256 platformFeeAmount;
        uint256 royaltyAmount;
        address royaltyRecipient;
    }

    /// @notice The tail every sale shares: confirm the seller can still deliver, move the token,
    ///         then split the price.
    /// @dev Callers write their own record first — a listing's status or remaining quantity, an
    ///      offer's status, a signed order's fill count — so the trade is already settled in
    ///      storage before this function makes any external call.
    function _settle(Settlement memory settlement)
        internal
        returns (address royaltyRecipient, uint256 platformFeeAmount, uint256 royaltyAmount)
    {
        return ForumOneSettlement.settle(_getStorage(), settlement);
    }

    // ============ Internal: Token Detection ============

    function _detectTokenType(MarketplaceStorage storage s, address assetContract) internal view returns (TokenType) {
        return ForumOneSettlement.detectTokenType(s, assetContract);
    }
}
