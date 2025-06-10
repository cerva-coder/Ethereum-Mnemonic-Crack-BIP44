import hashlib
import binascii
import os
import json
import math
import time
import multiprocessing

from mnemonic import Mnemonic
from bip32utils import BIP32Key
from ecdsa import SigningKey, SECP256k1
from eth_hash.auto import keccak

# ===== Bloom Filter utilities ====

def build_bloom(eth5_file, bloom_bin_path, meta_path, false_positive_rate=1e-6):
    """
    Builds a Bloom Filter from the address file (addr.txt).
    1) Counts how many lines (addresses) exist.
    2) Calculates bit size (m_bits) and number of hash functions (k) to achieve false_positive_rate.
    3) Allocates a bytearray with (m_bits // 8) + 1 bytes.
    4) For each address, normalizes it (adds '0x' if missing) and inserts it into the Bloom filter.
    5) Saves the bytearray to bloom_bin_path and {"m_bits": ..., "k": ...} to meta_path.
    """
    # 1) Count number of lines (n)
    n = 0
    with open(eth5_file, 'r') as f:
        for _ in f:
            n += 1

    # 2) Calculate m_bits and k
    #   m_bits ≈ -n * ln(p) / (ln 2)^2
    m_bits = math.ceil(-n * math.log(false_positive_rate) / (math.log(2) ** 2))
    m_bytes = (m_bits + 7) // 8
    #   k ≈ (m_bits / n) * ln 2
    k = max(1, round((m_bits / n) * math.log(2)))

    print(f"> [Bloom] number of addresses (n) = {n}")
    print(f"> [Bloom] false_positive_rate = {false_positive_rate}")
    print(f"> [Bloom] m_bits = {m_bits}, m_bytes = {m_bytes}")
    print(f"> [Bloom] number of hashes k = {k}")

    # 3) Create the bit array
    bitarray = bytearray(m_bytes)

    # 4) Insert each address into the Bloom filter
    with open(eth5_file, 'r') as f:
        for line in f:
            addr = line.strip().lower()
            if not addr.startswith('0x'):
                addr = '0x' + addr
            # For each hash function i, set the corresponding bit
            for i in range(k):
                # Concat: address + i (2 bytes little-endian) → SHA-256 hash
                digest = hashlib.sha256(addr.encode('utf-8') + i.to_bytes(2, 'little')).digest()
                pos = int.from_bytes(digest, 'big') % m_bits
                byte_index = pos // 8
                bit_index = pos % 8
                bitarray[byte_index] |= (1 << bit_index)

    # 5) Save the bytearray to the binary file
    with open(bloom_bin_path, 'wb') as bf:
        bf.write(bitarray)

    # 6) Save metadata in JSON (m_bits and k)
    meta = {"m_bits": m_bits, "k": k}
    with open(meta_path, 'w') as mf:
        json.dump(meta, mf)

    print("> Bloom Filter built and saved to disk.")

def load_bloom(bloom_bin_path, meta_path):
    """
    Loads a previously generated Bloom Filter.
    Returns (bitarray, m_bits, k).
    """
    with open(meta_path, 'r') as mf:
        meta = json.load(mf)
    m_bits = meta["m_bits"]
    k = meta["k"]
    with open(bloom_bin_path, 'rb') as bf:
        bitarray = bytearray(bf.read())
    return bitarray, m_bits, k

def bloom_contains(bitarray, m_bits, k, address):
    """
    Checks set membership of the address in the Bloom Filter.
    If all k bits are 1, returns True (may be in the list);
    if any bit is 0, returns False (definitely not in the list).
    """
    for i in range(k):
        digest = hashlib.sha256(address.encode('utf-8') + i.to_bytes(2, 'little')).digest()
        pos = int.from_bytes(digest, 'big') % m_bits
        byte_index = pos // 8
        bit_index = pos % 8
        if not (bitarray[byte_index] & (1 << bit_index)):
            return False
    return True

# ===== Ethereum functions and workflow =====

def generate_random_entropy():
    random_bytes = os.urandom(16)  # 128 bits
    return "0x" + binascii.hexlify(random_bytes).decode()

def check_entropy_and_convert(entropy):
    data = entropy.strip()
    data = binascii.unhexlify(data[2:])  # Remove '0x'
    if len(data) not in [16, 20, 24, 28, 32]:
        raise ValueError(f"Entropy length must be [16,20,24,28,32] bytes. Current: {len(data)}.")
    return data

def get_mnemonic_phrase():
    entropy = generate_random_entropy()
    data = check_entropy_and_convert(entropy)
    mnemo = Mnemonic("english")
    return mnemo.to_mnemonic(data)

def generate_eth_keys(mnemonic_phrase, index=0):
    mnemo = Mnemonic("english")
    seed = mnemo.to_seed(mnemonic_phrase)

    master_key = BIP32Key.fromEntropy(seed)
    purpose = master_key.ChildKey(44 + 0x80000000)
    coin_type = purpose.ChildKey(60 + 0x80000000)
    account = coin_type.ChildKey(0 + 0x80000000)
    change = account.ChildKey(0)
    address_key = change.ChildKey(index)

    private_key = binascii.hexlify(address_key.PrivateKey()).decode()
    sk = SigningKey.from_string(address_key.PrivateKey(), curve=SECP256k1)
    vk = sk.get_verifying_key()
    public_key = b"\x04" + vk.to_string()

    keccak_hash = keccak(public_key[1:])
    address = "0x" + keccak_hash[-20:].hex()
    return private_key, address

def search_address_in_file(eth_address, eth5_file):
    """
    If the Bloom filter suggests the address MAY be in the list,
    confirm by directly reading 'addr.txt' to be sure.
    This is only done if bloom_contains returns True.
    """
    with open(eth5_file, "r") as f:
        for line in f:
            addr = line.strip().lower()
            if not addr.startswith("0x"):
                addr = "0x" + addr
            if addr == eth_address:
                return True
    return False

def generate_and_compare_seeds(bloom_params, eth5_file, result_queue):
    pid = os.getpid()
    # Load the Bloom filter for this worker
    bitarray_, m_bits, k = load_bloom(bloom_params[0], bloom_params[1])
    result_queue.put(f"[Worker {pid}] started with Bloom filter")

    count = 0
    while True:
        try:
            mnemonic_phrase = get_mnemonic_phrase()
            private_key, eth_address = generate_eth_keys(mnemonic_phrase, 0)
            count += 1

            # 1) Check in the Bloom Filter (possible presence)
            if bloom_contains(bitarray_, m_bits, k, eth_address):
                # 2) Confirm by reading the file
                if search_address_in_file(eth_address, eth5_file):
                    result_queue.put(
                        f"[Worker {pid}] Collision found! Phrase: {mnemonic_phrase}, Private Key: {private_key}, Address: {eth_address}"
                    )
                    with open("collisions.txt", "a") as coll_file:
                        coll_file.write(
                            f"Phrase: {mnemonic_phrase}, Private Key: {private_key}, Address: {eth_address}\n"
                        )
                    break

            # Status every 1000 iterations (no longer 100)
            if count % 1000 == 0:
                result_queue.put(
                    f"[Worker {pid}] {count} generated. Seed: {mnemonic_phrase}  Address: {eth_address}"
                )

        except Exception as e:
            result_queue.put(f"[Worker {pid}] Error: {e}")

def worker_process(bloom_params, eth5_file, result_queue):
    generate_and_compare_seeds(bloom_params, eth5_file, result_queue)

def main():
    eth5_file = "addr.txt"         # Your public addresses file
    bloom_bin   = "bloom.bin"      # Where to save the Bloom bitarray
    bloom_meta  = "bloom_meta.json" # Where to save m_bits and k in JSON

    # If the Bloom Filter doesn't exist on disk, build it:
    if not (os.path.exists(bloom_bin) and os.path.exists(bloom_meta)):
        print("\nBuilding Bloom Filter... This may take a few minutes.")
        build_bloom(eth5_file, bloom_bin, bloom_meta, false_positive_rate=1e-6)

    # Parameters to pass to the worker: (bloom_bin path, bloom_meta path)
    bloom_params = (bloom_bin, bloom_meta)

    result_queue = multiprocessing.Queue()
    num_processes = multiprocessing.cpu_count()

    processes = []
    for _ in range(num_processes):
        p = multiprocessing.Process(
            target=worker_process,
            args=(bloom_params, eth5_file, result_queue)
        )
        p.start()
        processes.append(p)

    total_count = 0
    last_update = time.time()

    # Main loop: read from queue with 3s timeout
    while True:
        try:
            msg = result_queue.get(timeout=3)
            if msg:
                print(msg)
                if "generated" in msg:
                    total_count += 1000  # now counting 1000 per message
                    print(f"Approximate total generated: {total_count}")
                if "Collision found!" in msg:
                    print("### COLLISION FOUND! ###")
                    break

        except Exception:
            now = time.time()
            if now - last_update >= 10:
                print(f"Waiting... Approximate total generated so far: {total_count}")
                last_update = now

    # Terminate all processes
    for p in processes:
        p.terminate()
        p.join()

if __name__ == "__main__":
    main()
