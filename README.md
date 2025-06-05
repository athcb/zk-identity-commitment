# ZK Identity Commitment Generator

A Node.js script that generates **user-specific identity commitments** for Zero-Knowledge (ZK) circuits. It's a crucial step in preparing user identities for ZK-proof systems, ensuring eligibility and creating unique, cryptographically secure identifiers. 

---

## Overview

At a high level, the script performs the following steps:

1.  **Membership Check**: Verifies if the provided wallet address owns the specified ERC721 token. This is a mandatory gating mechanism.
2.  **Seed Generation**: A BIP39 mnemonic is generated, and from it, a secure 512-bit seed is deterministically derived. An optional passphrase can be used to enhance security.
3.  **Key Derivation**: Using HKDF (HMAC-based Key Derivation Function), two distinct secret keys (`zkSecretIdentity` and `zkIdentityNullifier`) are generated from the seed. These keys are crucial for the ZK proof.
4.  **Commitment Calculation**: The final ZK Identity Commitment is computed by applying the Poseidon hash function to the two derived secret keys. This commitment serves as the public representation of the ZK identity.

---

### Prerequisites

You'll need to set up a `.env` file with the following environment variables:

```
ERC721_ADDRESS="YOUR_ERC721_CONTRACT_ADDRESS"
PRIVATE_KEY="YOUR_WALLET_PRIVATE_KEY"
ALCHEMY_SEPOLIA_URL="YOUR_ALCHEMY_SEPOLIA_RPC_URL"
```

* `ERC721_ADDRESS`: The address of the ERC721 token contract used for membership verification.
* `PRIVATE_KEY`: The private key of the wallet you want to check for ERC721 ownership and generate the identity commitment for.
* `ALCHEMY_SEPOLIA_URL`: Your Alchemy Sepolia RPC URL (or any other Ethereum Sepolia RPC endpoint).

### Usage

To generate an identity commitment, simply run the script:

```bash
node generateCommitment.js 
```

It will output the generated mnemonic phrase, derived secret keys, and the final identity commitment. It will also perform the ERC721 membership check and exit with an error if the wallet is not an eligible member.
