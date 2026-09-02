# ForumOne

Smart contracts for the ForumOne marketplace, a curated, non-custodial
marketplace for collections on Ethereum, Base and Polygon.

- Non-custodial. Asset, fee, royalty and proceeds settle in one transaction.
- Curated on chain. Collections and payment currencies must be approved.
- Fixed-price listings in native currency or approved ERC-20s.
- Partial fills for ERC-1155. Batch buys of up to 50 listings.
- ERC-20 offers on specific tokens.
- Signed orders (EIP-712, ERC-1271) with platform co-signature and Merkle bulk signing.
- ERC-2981 royalties. Only the collection owner can set a royalty override.
- ERC-721C compatible.
- UUPS upgradeable.

Deployed at the same addresses on all three chains:

| Contract | Address |
| --- | --- |
| `ForumOneProxy` | `0x167AfC814c5614C33b7140f6095a784b1F562582` |
| `ForumOne` (implementation) | `0x4Cb7380B91C28A46DFfb626Bc5c0D5FAFC6C9391` |
| `ForumOneSettlement` | `0x96797eC12f3503c628E3034f44D6968864893844` |
| `ForumOneOrders` | `0x9bf7559C08d2ec17f888A1b2E3a09396c675bf2e` |
| `SignedOrderChecks` | `0x9d3e2d329393c155951611bD2Dfa619c8E51837d` |

Source is verified on Etherscan, Basescan and Polygonscan.

## License

MIT
