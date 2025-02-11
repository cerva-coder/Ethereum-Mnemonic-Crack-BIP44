import hashlib
import binascii
import os
import random
import string
from mnemonic import Mnemonic
from bip32utils import BIP32Key
from ecdsa import SigningKey, SECP256k1
from eth_hash.auto import keccak
import multiprocessing

# Function to generate random entropy
def generate_random_entropy():
    random_bytes = os.urandom(16)  # 128 bits
    return "0x" + binascii.hexlify(random_bytes).decode()

# Function to validate and convert entropy
def check_entropy_and_convert(entropy):
    data = entropy.strip()
    data = binascii.unhexlify(data[2:])
    if len(data) not in [16, 20, 24, 28, 32]:
        raise ValueError(f"Entropy length must be [16, 20, 24, 28, 32] bits. Current: {len(data)}.")
    return data

# Function to generate the checksum
def generate_checksum(data):
    h = hashlib.sha256(data).hexdigest()
    b = bin(int(binascii.hexlify(data), 16))[2:].zfill(len(data) * 8) + bin(int(h, 16))[2:].zfill(256)[:len(data) * 8 // 32]
    return b

# Function to generate the mnemonic phrase
def get_mnemonic_phrase():
    entropy = generate_random_entropy()
    data = check_entropy_and_convert(entropy)
    b = generate_checksum(data)
    mnemo = Mnemonic("english")
    return mnemo.to_mnemonic(data)  # The to_mnemonic function already converts to the phrase

# Function to generate private and public keys for Ethereum
def generate_eth_keys(mnemonic_phrase, index=0):
    mnemo = Mnemonic("english")
    seed = mnemo.to_seed(mnemonic_phrase)
    
    # Derive the master key
    master_key = BIP32Key.fromEntropy(seed)
    
    # BIP-44 path for Ethereum: m/44'/60'/0'/0/index
    purpose = master_key.ChildKey(44 + 0x80000000)
    coin_type = purpose.ChildKey(60 + 0x80000000)
    account = coin_type.ChildKey(0 + 0x80000000)
    change = account.ChildKey(0)
    address_key = change.ChildKey(index)
    
    private_key = binascii.hexlify(address_key.PrivateKey()).decode()
    
    # Generate the correct public key
    sk = SigningKey.from_string(address_key.PrivateKey(), curve=SECP256k1)
    vk = sk.get_verifying_key()
    public_key = b"\x04" + vk.to_string()
    
    # Generate Ethereum address
    keccak_hash = keccak(public_key[1:])
    address = "0x" + keccak_hash[-20:].hex()
    
    return private_key, address

# Function to generate and compare seeds with public addresses
def generate_and_compare_seeds(eth5_addresses, result_queue):
    count = 0
    found = False

    while True:
        mnemonic_phrase = get_mnemonic_phrase()
        private_key, eth_address = generate_eth_keys(mnemonic_phrase, 0)
        
        count += 1
        if eth_address in eth5_addresses:
            result_queue.put(f"Collision found! Phrase: {mnemonic_phrase}, Private Key: {private_key}, Public Key: {eth_address}")
            with open('collisions.txt', 'a') as coll_file:
                coll_file.write(f"Phrase: {mnemonic_phrase}, Private Key: {private_key}, Public Key: {eth_address}\n")
            found = True
        
        if count % 1000 == 0:
            result_queue.put(f"{count} generated, Phrase: {mnemonic_phrase}  Address: {eth_address}")
            if found:
                found = False

# Function to manage multiple processes
def worker_process(eth5_file, result_queue):
    with open(eth5_file, 'r') as f:
        eth5_addresses = set(f.read().splitlines())

    generate_and_compare_seeds(eth5_addresses, result_queue)

# Main function
def main():
    eth5_file = 'addr.txt'  # File containing the public addresses to compare
    
    # Create a queue for communication between processes
    result_queue = multiprocessing.Queue()

    # Determine the number of available cores for multiprocessing
    num_processes = multiprocessing.cpu_count()

    # Create a pool of processes to distribute the work
    processes = []
    for _ in range(num_processes):
        p = multiprocessing.Process(target=worker_process, args=(eth5_file, result_queue))
        processes.append(p)
        p.start()

    # Monitor results and display them in the prompt
    total_count = 0
    while True:
        result = result_queue.get()
        if result:
            print(result)
            if "generated" in result:
                total_count += 1000
                print(f"Total generated: {total_count}")
            if "Collision found!" in result:
                break
    
    # Wait for all processes to finish
    for p in processes:
        p.join()

if __name__ == "__main__":
    main()
