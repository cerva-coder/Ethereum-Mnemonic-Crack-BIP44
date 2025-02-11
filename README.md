# BIP-44 Ethereum Address Collision Finder

## Overview

The **BIP-44 Ethereum Address Collision Finder** is a Python script that generates Ethereum addresses from randomly created mnemonic phrases (using the BIP-39 standard) and compares these generated addresses with a list of known Ethereum addresses (provided as input). The main goal of this project is to detect collisions, where a generated Ethereum address matches one from a provided list. The script follows the **BIP-32** and **BIP-44** standards for key derivation, making it a suitable tool for working with hierarchical deterministic wallets (HD Wallets).

This script uses multiprocessing to efficiently generate and check Ethereum addresses across multiple CPU cores, significantly speeding up the process when dealing with large datasets.

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
    python script_name.py
    ```

3. The script will generate random mnemonic phrases, derive Ethereum addresses from them, and check them against the addresses in `addr.txt`. If a match is found, the script will log the collision in `collisions.txt` and print the details in the console.

## Output

- The script will periodically output the number of generated addresses and any collisions found in the console.
- Collisions will be saved in a `collisions.txt` file.

## Multithreading

This script utilizes multiprocessing to split the task of generating and checking Ethereum addresses across multiple CPU cores, speeding up the process considerably on systems with multiple cores.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
