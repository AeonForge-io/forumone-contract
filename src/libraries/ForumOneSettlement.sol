// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {IERC721} from "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import {IERC1155} from "@openzeppelin/contracts/token/ERC1155/IERC1155.sol";
import {IERC2981} from "@openzeppelin/contracts/interfaces/IERC2981.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

import {IForumOne} from "../interfaces/IForumOne.sol";
import {MarketplaceStorage} from "./MarketplaceStorage.sol";

/// @notice The arguments of one settled trade, gathered so `settle` takes a single stack slot.
/// @dev `platformFeeBps` is passed in rather than read from storage because a signed order carries
///      the fee it was signed under (see `docs/signed-orders-design.md` section 2). The stored
///      listing and offer paths pass `s.platformFeeBps`.
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
    function detectTokenType(address assetContract) external view returns (IForumOne.TokenType) {
        return _detectTokenType(assetContract);
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

        IForumOne.TokenType tokenType = _detectTokenType(assetContract);
        if (tokenType == IForumOne.TokenType.ERC721 && quantity != 1) {
            revert IForumOne.InvalidQuantity();
        }
        if (quantity == 0) revert IForumOne.InvalidQuantity();

        _validateOwnershipAndApproval(from, assetContract, tokenId, quantity, tokenType);
        _transferToken(from, to, assetContract, tokenId, quantity, tokenType);

        emit IForumOne.TokenTransferred(from, to, assetContract, tokenId, quantity, tokenType);
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

    function _detectTokenType(address assetContract) private view returns (IForumOne.TokenType) {
        try IERC165(assetContract).supportsInterface(type(IERC1155).interfaceId) returns (bool isERC1155) {
            if (isERC1155) return IForumOne.TokenType.ERC1155;
        } catch {}

        try IERC165(assetContract).supportsInterface(type(IERC721).interfaceId) returns (bool isERC721) {
            if (isERC721) return IForumOne.TokenType.ERC721;
        } catch {}

        revert IForumOne.TokenTypeNotSupported(assetContract);
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

    /// @dev The platform fee is taken first. Whatever the royalty source asks for — a curator
    ///      override or an ERC-2981 answer alike — is clamped to `totalPrice - platformFeeAmount`,
    ///      so a sale never reverts over the royalty amount and the seller may legitimately net
    ///      zero. The fee comes from the settlement, not from storage, because a signed order
    ///      carries the fee it was signed under; the clamp follows whichever value was passed, so
    ///      fee plus royalty never exceeds the price either way.
    function _payout(MarketplaceStorage storage s, Settlement memory settlement)
        private
        returns (address royaltyRecipient, uint256 platformFeeAmount, uint256 royaltyAmount)
    {
        uint256 totalPrice = settlement.totalPrice;

        platformFeeAmount = (totalPrice * settlement.platformFeeBps) / BPS_DENOMINATOR;

        (royaltyRecipient, royaltyAmount) = _resolveRoyalty(s, settlement.assetContract, settlement.tokenId, totalPrice);

        uint256 maxRoyalty = totalPrice - platformFeeAmount;
        if (royaltyAmount > maxRoyalty) {
            royaltyAmount = maxRoyalty;
        }

        // Unreachable after the clamp above; kept as a named guard on the invariant.
        if (platformFeeAmount + royaltyAmount > totalPrice) {
            revert IForumOne.TotalFeesExceedPrice(platformFeeAmount + royaltyAmount, totalPrice);
        }

        uint256 sellerProceeds = totalPrice - platformFeeAmount - royaltyAmount;

        _transferCurrency(settlement.currency, settlement.buyer, s.platformFeeRecipient, platformFeeAmount);
        if (royaltyAmount > 0) {
            _transferCurrency(settlement.currency, settlement.buyer, royaltyRecipient, royaltyAmount);
        }
        _transferCurrency(settlement.currency, settlement.buyer, settlement.seller, sellerProceeds);
    }

    // ============ Internal: Royalty Resolution ============

    /// @dev A curator-set override always wins; only when none is set is the collection asked for
    ///      an ERC-2981 answer. That answer is read with a raw `staticcall` and decoded by hand so
    ///      nothing a collection returns can revert the sale. Falls through to no royalty
    ///      (`address(0)`, `0`) when:
    ///        - the `staticcall` fails (revert, or a non-contract address);
    ///        - fewer than 64 bytes of return data;
    ///        - the recipient word has nonzero upper bits (not a clean address);
    ///        - the decoded recipient is `address(0)`, or the amount is zero.
    ///      A collection with a broken `royaltyInfo` therefore stays tradeable. The returned
    ///      amount is not yet clamped; `_payout` applies the `price - platformFeeAmount` ceiling.
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

        (bool success, bytes memory returnData) =
            assetContract.staticcall(abi.encodeCall(IERC2981.royaltyInfo, (tokenId, salePrice)));

        if (!success || returnData.length < 64) return (address(0), 0);

        uint256 recipientWord;
        uint256 amountWord;
        assembly ("memory-safe") {
            recipientWord := mload(add(returnData, 0x20))
            amountWord := mload(add(returnData, 0x40))
        }

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
