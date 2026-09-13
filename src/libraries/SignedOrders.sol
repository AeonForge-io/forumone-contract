// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @title SignedOrders
/// @notice The EIP-712 order types of the gasless flow, and the platform attestation that
///         authorizes one fill of one of them.
/// @dev The order hash a caller sees everywhere — in `SignedListingFilled`, in
///      `cancelSignedOrders`, in a `FulfillmentAuthorization` — is the EIP-712 struct hash produced
///      here, not the signing digest. The digest is that hash under the marketplace's domain, so
///      one order has one hash on every chain while its signature is valid on exactly one.
library SignedOrders {
    /// @notice A listing the seller signed instead of writing to storage.
    /// @dev `signer` is carried rather than recovered because `SignatureChecker` needs a claimed
    ///      signer to route between ECDSA and ERC-1271. The token standard is deliberately absent:
    ///      it is derived on chain, so an order can never disagree with the collection about it.
    ///      `platformFeeBps` is the fee the sale pays, fixed at signing.
    struct SignedListing {
        address signer;
        address assetContract;
        uint256 tokenId;
        uint256 quantity;
        address currency;
        uint256 pricePerToken;
        uint256 expiration;
        uint256 platformFeeBps;
        uint256 counter;
        uint256 salt;
    }

    /// @notice A bid the offeror signed instead of writing to storage: "X per unit, up to N" on
    ///         one token id, on any id in a set, or on a whole collection.
    /// @dev `currency` must be a nonzero allowlisted ERC-20: a signature cannot pull native
    ///      currency, so there is no native signed offer. The offer fills in parts, by many
    ///      holders, until `quantity` units have settled against its hash.
    ///
    ///      `criteriaRoot` is zero for an offer on exactly `tokenId`. Otherwise it is the Merkle
    ///      root of the eligible token ids of `assetContract` — leaf `keccak256(abi.encode(id))`,
    ///      OpenZeppelin sorted-pair hashing — and `tokenId` is ignored; the accepting leg names
    ///      the id it sells and proves it against the root. One collection per offer, one price
    ///      per unit per offer: a different price or a second collection is a second order.
    struct SignedOffer {
        address signer;
        address assetContract;
        uint256 tokenId;
        bytes32 criteriaRoot;
        uint256 quantity;
        address currency;
        uint256 pricePerToken;
        uint256 expiration;
        uint256 platformFeeBps;
        uint256 counter;
        uint256 salt;
    }

    /// @notice The platform's attestation that one order may be filled, now, by one caller.
    /// @dev `fulfiller` names the buyer; `address(0)` means any caller and is reserved for open
    ///      broadcast flows. `expiry` is short-lived by design — cancelling an order is the
    ///      service declining to attest it again.
    struct Cosignature {
        address fulfiller;
        uint64 expiry;
        bytes signature;
    }

    /// @notice One leg of `batchFulfillSignedListings`, carrying its own attestation.
    struct SignedFill {
        SignedListing order;
        bytes signature;
        uint256 quantity;
        Cosignature cosig;
    }

    /// @notice One acceptance of a signed offer — the single `acceptSignedOffer` call and every
    ///         leg of `batchAcceptSignedOffers` take this shape.
    /// @dev `tokenId` is the token the caller sells: it must equal `order.tokenId` when the order
    ///      has no criteria root, and must prove against the root through `proof` when it has
    ///      one (`proof` is ignored otherwise). `quantity` is the units sold by this leg —
    ///      exactly 1 for ERC-721 — and counts against the order's `quantity`.
    ///      `minSellerProceeds` is the least the caller will net from this leg after the platform
    ///      fee and the royalty, in the order's currency; settlement reverts
    ///      `SellerProceedsBelowMinimum` below it, so a royalty raised between the seller's quote
    ///      and the accept landing cannot quietly shrink their payout. Zero disables the check.
    struct SignedOfferAccept {
        SignedOffer order;
        bytes signature;
        uint256 tokenId;
        uint256 quantity;
        uint256 minSellerProceeds;
        bytes32[] proof;
        Cosignature cosig;
    }

    bytes32 internal constant SIGNED_LISTING_TYPEHASH = keccak256(
        "SignedListing(address signer,address assetContract,uint256 tokenId,uint256 quantity,address currency,uint256 pricePerToken,uint256 expiration,uint256 platformFeeBps,uint256 counter,uint256 salt)"
    );

    bytes32 internal constant SIGNED_OFFER_TYPEHASH = keccak256(
        "SignedOffer(address signer,address assetContract,uint256 tokenId,bytes32 criteriaRoot,uint256 quantity,address currency,uint256 pricePerToken,uint256 expiration,uint256 platformFeeBps,uint256 counter,uint256 salt)"
    );

    bytes32 internal constant FULFILLMENT_AUTHORIZATION_TYPEHASH =
        keccak256("FulfillmentAuthorization(bytes32 orderHash,address fulfiller,uint256 expiry)");

    /// @notice The `encodeType` strings the two order type hashes above are the hash of.
    /// @dev Written out a second time rather than derived: Solidity inlines a constant's
    ///      expression at every use, so a `constant` defined as `keccak256(bytes(TYPE_STRING))`
    ///      would re-hash ~200 bytes on every fill. The duplication is pinned by
    ///      `test_TypeStringsHashToTheOrderTypehashes`, which fails if the two ever drift. Only
    ///      the bulk paths read these: a bulk type string ends with the component type, so the
    ///      text, not just its hash, has to be available on chain.
    string internal constant SIGNED_LISTING_TYPE =
        "SignedListing(address signer,address assetContract,uint256 tokenId,uint256 quantity,address currency,uint256 pricePerToken,uint256 expiration,uint256 platformFeeBps,uint256 counter,uint256 salt)";

    string internal constant SIGNED_OFFER_TYPE =
        "SignedOffer(address signer,address assetContract,uint256 tokenId,bytes32 criteriaRoot,uint256 quantity,address currency,uint256 pricePerToken,uint256 expiration,uint256 platformFeeBps,uint256 counter,uint256 salt)";

    /// @notice The Merkle leaf a criteria offer's root is built over, for one eligible token id.
    /// @dev A 32-byte preimage where every inner node hashes 64 bytes, so a leaf can never be
    ///      passed off as a node or the reverse. The site builds the tree with the same leaf and
    ///      OpenZeppelin's sorted-pair node hashing.
    function criteriaLeaf(uint256 tokenId) internal pure returns (bytes32) {
        return keccak256(abi.encode(tokenId));
    }

    /// @notice The deepest bulk tree the contract will verify: 2**24 orders in one signature.
    /// @dev Seaport's ceiling, adopted for the same reason — the height fixes the type string the
    ///      wallet renders, so the set of type hashes has to be finite, and 24 is far past any
    ///      plausible batch while keeping the proof under 768 bytes of calldata.
    uint256 internal constant MAX_BULK_ORDER_HEIGHT = 24;

    /// @notice The shortest and longest an extended (bulk) signature can be.
    /// @dev A 64-byte compact signature plus the 3-byte key plus one proof node, and a 65-byte
    ///      signature plus the key plus 24 proof nodes. Exposed so the fill path can rule out the
    ///      bulk reading with one comparison, before paying for the call into
    ///      `decodeBulkSignature` at all — that is what keeps single-order fills cheap.
    uint256 internal constant MIN_BULK_SIGNATURE_LENGTH = 99;
    uint256 internal constant MAX_BULK_SIGNATURE_LENGTH = 836;

    /// @notice The ceiling on the platform fee, in basis points.
    /// @dev The only bound settlement puts on a signed order's fee, and the ceiling the stored
    ///      fee is set under. Lives here because `ForumOne` and `SignedOrderChecks` both enforce
    ///      it and must never disagree.
    uint16 internal constant MAX_PLATFORM_FEE_BPS = 500;

    /// @notice The key one signed order's on-chain record lives under.
    /// @dev Keyed by signer as well as hash, so `cancelSignedOrders` needs no signature to prove
    ///      the caller owns the record it writes. Shared by the contract and the checks library so
    ///      a cancellation and a fill can never disagree about which slot they mean.
    function statusKey(address signer, bytes32 orderHash) internal pure returns (bytes32) {
        return keccak256(abi.encode(signer, orderHash));
    }

    /// @notice The EIP-712 struct hash of a signed listing.
    function hash(SignedListing calldata order) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                SIGNED_LISTING_TYPEHASH,
                order.signer,
                order.assetContract,
                order.tokenId,
                order.quantity,
                order.currency,
                order.pricePerToken,
                order.expiration,
                order.platformFeeBps,
                order.counter,
                order.salt
            )
        );
    }

    /// @notice The EIP-712 struct hash of a signed offer.
    function hash(SignedOffer calldata order) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                SIGNED_OFFER_TYPEHASH,
                order.signer,
                order.assetContract,
                order.tokenId,
                order.criteriaRoot,
                order.quantity,
                order.currency,
                order.pricePerToken,
                order.expiration,
                order.platformFeeBps,
                order.counter,
                order.salt
            )
        );
    }

    /// @notice The EIP-712 struct hash of the co-signature payload for one fill.
    function hashFulfillmentAuthorization(bytes32 orderHash, address fulfiller, uint256 expiry)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(FULFILLMENT_AUTHORIZATION_TYPEHASH, orderHash, fulfiller, expiry));
    }

    // ============ Bulk (Merkle) Signatures ============
    //
    // The pattern, and the wire format, are Seaport's (MIT). One signature covers a whole tree of
    // orders, and the thing signed is a *typed* structure rather than a bare root, so a wallet can
    // still render every order in it: see docs/signed-orders-design.md section 14.

    /// @notice The EIP-712 type hash of the bulk wrapper for a tree of the given height.
    /// @dev The wrapper is a one-member struct whose member is a nested fixed array of orders:
    ///
    ///          BulkSignedListing(SignedListing[2]...[2] tree)SignedListing(address signer,...)
    ///
    ///      with `height` repetitions of `[2]`. The type string is the primary type followed by
    ///      its referenced types in alphabetical order; there is exactly one referenced type here,
    ///      so the ordering rule is satisfied by concatenation. Derived rather than looked up from
    ///      a table of 24 constants because deriving is a few hundred bytes of code against
    ///      several kilobytes of table.
    /// @param height The tree height, 1..`MAX_BULK_ORDER_HEIGHT`.
    /// @param isOffer True for a tree of `SignedOffer` leaves, false for `SignedListing`.
    function bulkTypehash(uint256 height, bool isOffer) internal pure returns (bytes32) {
        bytes memory dimensions = new bytes(height * 3);
        for (uint256 i = 0; i < dimensions.length; i += 3) {
            dimensions[i] = "[";
            dimensions[i + 1] = "2";
            dimensions[i + 2] = "]";
        }

        return isOffer
            ? keccak256(abi.encodePacked("BulkSignedOffer(SignedOffer", dimensions, " tree)", SIGNED_OFFER_TYPE))
            : keccak256(abi.encodePacked("BulkSignedListing(SignedListing", dimensions, " tree)", SIGNED_LISTING_TYPE));
    }

    /// @notice Reads a signature that may carry a Merkle proof, and folds the leaf up to the bulk
    ///         struct hash the maker actually signed.
    ///
    /// @dev **Wire format.** A plain signature is 64 bytes (ERC-2098 compact) or 65. An extended
    ///      one appends a 3-byte big-endian key and `height` 32-byte proof nodes:
    ///
    ///          [ signature (64 or 65) ][ uint24 key ][ bytes32 proof[height] ]
    ///
    ///      The inner signature's length is recoverable from the total: `64 + 3 + 32h` is
    ///      3 modulo 32 and `65 + 3 + 32h` is 4, and no other combination lands on either. That is
    ///      Seaport's parity trick, tightened from modulo 2 to modulo 32 so a proof that is not a
    ///      whole number of words is rejected outright instead of being silently truncated.
    ///      The 64-byte form is read but only ever *verified* through ERC-1271: OpenZeppelin's
    ///      `ECDSA` accepts nothing but the 65-byte form out of a `bytes`, for inner and
    ///      single-order signatures alike.
    ///
    ///      **The fold.** Level `i` uses bit `i` of the key: 0 means the running node is the left
    ///      input, 1 means it is the right one, and the node is `keccak256` of the raw 64-byte
    ///      concatenation. That is exactly what EIP-712 `encodeData` degenerates to for a member
    ///      of type `SignedListing[2]...[2]`: an array encodes as the hash of its encoded elements
    ///      concatenated, a struct element encodes as its struct hash, so each level is
    ///      `keccak256(left || right)`. The result is the encoding of the `tree` member, and
    ///      `keccak256(typeHash || tree)` is then the wrapper's struct hash by definition.
    ///
    ///      **Detection is by shape, and failure is not fatal.** A contract signer's ERC-1271
    ///      signature is arbitrary-length and can land on a bulk-shaped length by coincidence — a
    ///      132-byte Safe signature is 4 modulo 32. So this function only reports whether the
    ///      bytes *could* be a bulk signature; the caller tries that reading first and falls back
    ///      to verifying the whole blob against the single-order digest, so such a signature
    ///      still verifies.
    ///
    /// @param leaf The order's own EIP-712 struct hash — the same hash used for fill tracking,
    ///        cancellation and the co-signature. Bulk signing changes nothing about it.
    /// @param signature The signature as it arrived from the caller.
    /// @param isOffer True when the leaf is a `SignedOffer`.
    /// @return decoded Whether `signature` has the shape of an extended signature at all.
    /// @return bulkStructHash The struct hash of the bulk wrapper, meaningless when `decoded` is
    ///         false.
    /// @return innerSignature The leading 64 or 65 bytes, empty when `decoded` is false.
    function decodeBulkSignature(bytes32 leaf, bytes calldata signature, bool isOffer)
        internal
        pure
        returns (bool decoded, bytes32 bulkStructHash, bytes calldata innerSignature)
    {
        uint256 length = signature.length;
        if (length < MIN_BULK_SIGNATURE_LENGTH || length > MAX_BULK_SIGNATURE_LENGTH) {
            return (false, bytes32(0), signature[:0]);
        }

        uint256 signatureLength;
        uint256 remainder = length % 32;
        if (remainder == 3) {
            signatureLength = 64;
        } else if (remainder == 4) {
            signatureLength = 65;
        } else {
            return (false, bytes32(0), signature[:0]);
        }

        // Exact by construction: the modulus above already fixed the whole layout.
        uint256 height = (length - signatureLength - 3) / 32;
        if (height == 0 || height > MAX_BULK_ORDER_HEIGHT) return (false, bytes32(0), signature[:0]);

        uint256 key = uint256(uint24(bytes3(signature[signatureLength:signatureLength + 3])));
        // Only the low `height` bits address a leaf. Rejecting the rest costs one comparison and
        // removes a malleability: without it, several distinct signatures fold to one digest.
        // Seaport ignores the high bits; this is the one place the two deliberately differ.
        if (key >> height != 0) return (false, bytes32(0), signature[:0]);

        bytes calldata proof = signature[signatureLength + 3:];

        bytes32 node = leaf;
        for (uint256 i = 0; i < height; ++i) {
            bytes32 sibling = bytes32(proof[i * 32:(i * 32) + 32]);
            node = (key >> i) & 1 == 0
                ? keccak256(abi.encodePacked(node, sibling))
                : keccak256(abi.encodePacked(sibling, node));
        }

        return (true, keccak256(abi.encode(bulkTypehash(height, isOffer), node)), signature[:signatureLength]);
    }
}
