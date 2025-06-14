# BIP-44 Ethereum Mnemonic Crack

## Overview

The **BIP-44 Ethereum Address Collision Finder** is a Python script designed to generate Ethereum addresses from randomly generated mnemonic phrases (following the BIP-39 standard). It then compares these generated addresses against a given list of known Ethereum addresses (provided by the user) to detect any collisions. The project is based on **BIP-32** and **BIP-44** standards for key derivation, making it a suitable tool for working with **hierarchical deterministic (HD) wallets**—a common feature in popular wallets such as **Trust Wallet**, **BlueWallet**, and others.

### What is BIP-44?

**BIP-44** (Bitcoin Improvement Proposal 44) is a standard used for **HD wallets**, which allows for the generation of multiple cryptocurrency addresses from a single master seed phrase. This standard is used by many well-known wallets (e.g., **Trust Wallet**, **BlueWallet**, **Exodus**, and others) to derive addresses for different cryptocurrencies in a structured way.

The BIP-44 standard specifies a specific derivation path:  
`m / purpose' / coin_type' / account' / change' / index`  
For Ethereum, the **coin_type** is 60, as defined by BIP-44. This path ensures that a wallet can derive Ethereum addresses (and other coins) from the same mnemonic phrase using a unique and consistent method. By following BIP-44, wallets can generate a sequence of addresses deterministically, meaning they can regenerate all past addresses and private keys from a single seed.

This, the script uses the **BIP-44 path for Ethereum** (`m/44'/60'/0'/0/index`) to derive addresses in a standardized manner, allowing for the efficient comparison of generated addresses against a set of known Ethereum addresses.

---
## Advantages

Probabilistic Advantage via Entropy Constraints:  This script generates 12-word BIP-39 mnemonic phrases, which are limited to a keyspace of 128 bits of entropy (plus checksum), compared to 256-bit entropy in raw private key generation. This significantly reduces the total number of possibilities, making each attempt statistically more efficient. While collisions remain extremely rare, the search is focused on a mathematically smaller and structured set of possible wallets — increasing the odds compared to brute-forcing random 256-bit keys.

While each seed phrase allows for the derivation of a theoretically infinite number of addresses, in practice the most commonly used address by users is the first derived address (index 0) in the standard BIP-44 path (m/44'/60'/0'/0/0). This is due to the convention adopted by popular wallets such as Trust Wallet, MetaMask, and BlueWallet, which by default display and use the derivation seed address for everyday transactions.

Single Derivation Path Advantage: Ethereum uses a single public address derivation format. Each private key corresponds directly to one unique Ethereum address. Unlike Bitcoin, which supports multiple address types (P2PKH, P2SH, Bech32), Ethereum's simple and direct derivation method significantly increases the script's effectiveness by reducing complexity and enhancing speed.

---

## Key Features
- **High-performance Bloom Filter for Ethereum Address Matching**: Uses a dynamically computed Bloom filter based on the number of addresses and desired false positive rate (default: 1e-6), allowing membership tests with O(1) complexity. Each address is converted into multiple SHA-256 hashes to define specific bits in a compact array, drastically reducing memory usage and avoiding disk reads during scanning. Ideal for massive seed/mnemonic scanning with millions of addresses, while maintaining high efficiency and scalability.
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
    pycryptodome
    colorama
    rich
    ```

3. Install dependencies using pip:

    ```
    pip install -r requirements.txt
    ```
4. If you get an error installing the libraries in Python, install Microsoft Visual C++ 14.0 or greater "Microsoft C++ Build Tools": https://visualstudio.microsoft.com/visual-cpp-build-tools/
Select both check boxes for Desktop Development with C++ and .NET Desktop Build Tools during installation.

5. Prepare a text file (e.g., `addr.txt`) containing the list of Ethereum addresses to compare against.

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


## Donation
If you find the program useful and want to support its development, please donate to the following Ethereum address:

Ethereum address: 0x5CD8E5F5E2750B1bBA9ac41970019a3DB8052Fa5

Your donations help keep the project active and contribute to its maintenance and continuous improvements. We appreciate your support!

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
