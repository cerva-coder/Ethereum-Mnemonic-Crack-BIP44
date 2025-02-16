# BIP-44 Ethereum Mnemonic Crack

## Overview

The **BIP-44 Ethereum Address Collision Finder** is a Python script designed to generate Ethereum addresses from randomly generated mnemonic phrases (following the BIP-39 standard). It then compares these generated addresses against a given list of known Ethereum addresses (provided by the user) to detect any collisions. The project is based on **BIP-32** and **BIP-44** standards for key derivation, making it a suitable tool for working with **hierarchical deterministic (HD) wallets**—a common feature in popular wallets such as **Trust Wallet**, **BlueWallet**, and others.

### What is BIP-44?

**BIP-44** (Bitcoin Improvement Proposal 44) is a standard used for **HD wallets**, which allows for the generation of multiple cryptocurrency addresses from a single master seed phrase. This standard is used by many well-known wallets (e.g., **Trust Wallet**, **BlueWallet**, **Exodus**, and others) to derive addresses for different cryptocurrencies in a structured way.

The BIP-44 standard specifies a specific derivation path:  
`m / purpose' / coin_type' / account' / change' / index`  
For Ethereum, the **coin_type** is 60, as defined by BIP-44. This path ensures that a wallet can derive Ethereum addresses (and other coins) from the same mnemonic phrase using a unique and consistent method. By following BIP-44, wallets can generate a sequence of addresses deterministically, meaning they can regenerate all past addresses and private keys from a single seed.

---

## Why Ethereum?

Ethereum is a blockchain platform that, like Bitcoin, uses public-private key pairs for transaction signing and address generation. However, unlike Bitcoin—which supports multiple address types like P2PKH, P2SH, and SegWit addresses—Ethereum has a simpler model. Each Ethereum address is derived from the public key using **Keccak-256** hashing, and **each Ethereum private key** corresponds to a single unique address. 

### Key Differences Between Ethereum and Bitcoin in Terms of Address Derivation:

- **Bitcoin** supports multiple address formats:
  - **P2PKH (Pay-to-PubKey-Hash)**: Traditional Bitcoin addresses starting with `1`.
  - **P2SH (Pay-to-Script-Hash)**: Segregated Witness (SegWit) addresses starting with `3`.
  - **Bech32**: A newer SegWit address format that starts with `bc1`.

- **Ethereum**, on the other hand, has a single address format:
  - **Standard Ethereum Address**: Derived directly from the public key, and the address is the last 20 bytes of the **Keccak-256** hash of the public key, prefixed with `0x`.

Because of Ethereum's simpler structure, it only generates **one address per private key**. This is in contrast to Bitcoin's multiple address types derived from the same private key, making Ethereum address generation relatively straightforward and predictable. 

Thus, the script uses the **BIP-44 path for Ethereum** (`m/44'/60'/0'/0/index`) to derive addresses in a standardized manner, allowing for the efficient comparison of generated addresses against a set of known Ethereum addresses.

### Why Ethereum for This Project?

While Ethereum's address generation is simpler compared to Bitcoin (due to the absence of multiple address types), its widespread use and the need for collision detection in large datasets still make it a valuable target for this project. Additionally, **Ethereum's deterministic address derivation** ensures that each mnemonic phrase always generates the same set of addresses, making it easier to identify potential address collisions when comparing with an existing list of known addresses.

---

## Key Features

- **Entropy Generation**: Random entropy is generated and converted into a valid format, followed by checksum validation.
- **Mnemonic Phrase Generation**: The script generates a 12-word mnemonic phrase based on random entropy, following the BIP-39 standard.
- **BIP-44 Key Derivation**: The generated mnemonic is used to derive Ethereum private and public keys using the BIP-32 and BIP-44 standards, ensuring proper key derivation for Ethereum (m/44'/60'/0'/0/index).
- **Ethereum Address Generation**: Public keys are hashed using Keccak-256 to generate Ethereum addresses.
- **Collision Detection**: The generated Ethereum addresses are compared to a provided list of known addresses, and collisions are logged if found.
- **Multiprocessing**: The script uses multiprocessing to run in parallel across multiple CPU cores, making it efficient for large-scale address generation.

## Installation

1. Clone the repository or download the script.
2. Install the required dependencies by creating a `requirements.txt`:

    ```
    mnemonic
    bip32utils
    ecdsa
    eth-hash
    ```

3. Install dependencies using pip:

    ```
    pip install -r requirements.txt
    ```

4. Prepare a text file (e.g., `addr.txt`) containing the list of Ethereum addresses to compare against.

## Usage

1. Place your `addr.txt` file in the same directory as the script. This file should contain one Ethereum address per line.
2. Run the script:

    ```
    python eth_mnm_finder.py
    ```

3. The script will generate random mnemonic phrases, derive Ethereum addresses from them, and check them against the addresses in `addr.txt`. If a match is found, the script will log the collision in `collisions.txt` and print the details in the console.

## Output

- The script will periodically output the number of generated addresses and any collisions found in the console.
- Collisions will be saved in a `collisions.txt` file.
- The script is configured to display the count every 1,000 addresses checked, although this value can be adjusted directly in the code. During this process, it also provides information about the last key checked, including its mnemonic phrase and public key, to the terminal. This information is presented for validation purposes only. You can confirm the accuracy of the data by using an appropriate online converter.

## Multithreading

- This script utilizes multiprocessing to split the task of generating and checking Ethereum addresses across multiple CPU cores, speeding up the process considerably on systems with multiple cores.
- Because of multiprocessing, the script displays the count of each core separately, since the task is executed by each core, anyway, the total count is displayed, being the sum of all cores.

## List of addresses for collision
-The repository provides a list of 10k richest Ethereum addresses. However, you can provide your own list. In internal testing, I worked with 13 million target addresses, which cost approximately 9 GB of total RAM, while the file was only 2 GB, but when loading into RAM it becomes heavier. 
## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
