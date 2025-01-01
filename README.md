This Java library is designed to provide an easy and secure way to generate BIP-39 compatible mnemonic phrases and derive BIP-84 extended keys. With this library, you can quickly create a 12-word mnemonic, derive the corresponding zpub (extended public key), and use it for cold storage solutions.

Security: The zpub (extended public key) enables you to import your wallet into watch-only wallets without revealing your private keys, making it ideal for cold storage setups.

Focuses solely on BIP-84, the most widely used standard for generating SegWit (bech32) addresses.

Only uses the org.bouncycastle library for elliptic curve calculations.

