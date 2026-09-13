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
| `ForumOne` (implementation) | `0x9c71EB1C355D8B57462a30bCF3c2D64Ac4736F29` |
| `ForumOneSettlement` | `0xe428d8579B35A664d5AFa9Af0A8B79628F545e5a` |
| `ForumOneOrders` | `0x9B4779fb6D8531430f7a77e308497e9A69a3bc3d` |
| `SignedOrderChecks` | `0x14dc3Be49A120Fde8d24a9a82f925C5Ba2fB842B` |

Source is verified on Etherscan, Basescan and Polygonscan.

## License

MIT
