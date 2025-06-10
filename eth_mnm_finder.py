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

# ===== Proof-of-Concept Constants =====
POC_SEED = "riot sail ask school orphan tilt analyst dream gun shop mutual leader"
POC_ADDRESS = "0x885becad3144016b140d3adf8f78c9001db64e2a"

def ensure_poc(addr_file, address):
    """
    Ensure that POC_ADDRESS is the first line of addr.txt,
    removing any older duplicates and rewriting the file.
    """
    normalized = address.lower()
    if not normalized.startswith("0x"):
        normalized = "0x" + normalized
    existing = []
    if os.path.exists(addr_file):
        with open(addr_file, 'r') as f:
            existing = f.readlines()
        existing = [line for line in existing if line.strip().lower() != normalized]
    with open(addr_file, 'w') as f:
        f.write(normalized + '\n')
        f.writelines(existing)

def build_bloom(addr_file, bloom_path, meta_path, false_positive_rate=1e-6):
    """
    Builds a Bloom filter from addr.txt:
    1) Count total addresses (n).
    2) Compute bit size (m_bits) and hash count (k) for target false positive rate.
    3) Allocate bytearray of size (m_bits // 8) + 1.
    4) Normalize each address and insert into filter.
    5) Write filter to bloom_path and {"m_bits":…, "k":…} to meta_path.
    """
    # 1) Count lines
    n = sum(1 for _ in open(addr_file, 'r'))

    # 2) Compute parameters
    m_bits = math.ceil(-n * math.log(false_positive_rate) / (math.log(2) ** 2))
    m_bytes = (m_bits + 7) // 8
    k = max(1, round((m_bits / n) * math.log(2)))

    # Auxiliary prints
    print(f"> [Bloom] number of addresses = {n}")
    print(f"> [Bloom] false positive rate = {false_positive_rate}")
    print(f"> [Bloom] m_bits = {m_bits}, m_bytes = {m_bytes}")
    print(f"> [Bloom] number of hash functions = {k}")

    # 3) Initialize bit array
    bitarray = bytearray(m_bytes)

    # 4) Insert each address
    with open(addr_file, 'r') as f:
        for line in f:
            addr = line.strip().lower()
            if not addr.startswith("0x"):
                addr = "0x" + addr
            for i in range(k):
                digest = hashlib.sha256(addr.encode() + i.to_bytes(2, 'little')).digest()
                pos = int.from_bytes(digest, 'big') % m_bits
                bitarray[pos // 8] |= (1 << (pos % 8))

    # 5) Save filter and metadata
    with open(bloom_path, 'wb') as bf:
        bf.write(bitarray)
    with open(meta_path, 'w') as mf:
        json.dump({"m_bits": m_bits, "k": k}, mf)

    print("> Bloom filter built and saved to disk.")

def load_bloom(bloom_path, meta_path):
    with open(meta_path, 'r') as mf:
        meta = json.load(mf)
    with open(bloom_path, 'rb') as bf:
        bitarray = bytearray(bf.read())
    return bitarray, meta["m_bits"], meta["k"]

def bloom_contains(bitarray, m_bits, k, address):
    for i in range(k):
        digest = hashlib.sha256(address.encode() + i.to_bytes(2, 'little')).digest()
        pos = int.from_bytes(digest, 'big') % m_bits
        if not (bitarray[pos // 8] & (1 << (pos % 8))):
            return False
    return True

def generate_random_entropy():
    return "0x" + binascii.hexlify(os.urandom(16)).decode()

def check_entropy_and_convert(entropy):
    data = binascii.unhexlify(entropy[2:])
    if len(data) not in [16,20,24,28,32]:
        raise ValueError(f"Entropy length must be one of [16,20,24,28,32] bytes, got {len(data)}.")
    return data

def get_mnemonic_phrase():
    data = check_entropy_and_convert(generate_random_entropy())
    return Mnemonic("english").to_mnemonic(data)

def generate_eth_keys(mnemonic_phrase, index=0):
    seed = Mnemonic("english").to_seed(mnemonic_phrase)
    master = BIP32Key.fromEntropy(seed)
    purpose = master.ChildKey(44 + 0x80000000)
    coin = purpose.ChildKey(60 + 0x80000000)
    account = coin.ChildKey(0 + 0x80000000)
    change = account.ChildKey(0)
    key = change.ChildKey(index)

    priv = binascii.hexlify(key.PrivateKey()).decode()
    sk = SigningKey.from_string(key.PrivateKey(), curve=SECP256k1)
    pub = b"\x04" + sk.get_verifying_key().to_string()
    address = "0x" + keccak(pub[1:])[-20:].hex()
    return priv, address

def search_address_in_file(address, addr_file):
    with open(addr_file, 'r') as f:
        for line in f:
            a = line.strip().lower()
            if not a.startswith("0x"):
                a = "0x" + a
            if a == address.lower():
                return True
    return False

def generate_and_compare_seeds(bloom_params, addr_file, queue):
    pid = os.getpid()
    bitarray_, m_bits, k = load_bloom(*bloom_params)
    queue.put(f"[Worker {pid}] started with Bloom filter")

    count = 0
    while True:
        mnemonic = get_mnemonic_phrase()
        _, address = generate_eth_keys(mnemonic)
        count += 1

        if bloom_contains(bitarray_, m_bits, k, address):
            if search_address_in_file(address, addr_file):
                queue.put(f"[Worker {pid}] Collision found! Phrase: {mnemonic}, Address: {address}")
                with open("collisions.txt", "a") as coll:
                    coll.write(f"Phrase: {mnemonic}, Address: {address}\n")
                break

        if count % 1000 == 0:
            queue.put(f"[Worker {pid}] {count} generated. Phrase: {mnemonic}, Address: {address}")

def worker_process(bloom_params, addr_file, queue):
    generate_and_compare_seeds(bloom_params, addr_file, queue)

def main():
    addr_file = "addr.txt"
    bloom_path = "bloom.bin"
    meta_path = "bloom_meta.json"

    # 1) Ensure PoC is at the top of addr.txt
    ensure_poc(addr_file, POC_ADDRESS)

    # 2) Build Bloom filter if missing
    if not (os.path.exists(bloom_path) and os.path.exists(meta_path)):
        print("\nBuilding Bloom filter… this may take a few minutes.")
        build_bloom(addr_file, bloom_path, meta_path)

    # 3) Run PoC test before workers
    bitarray_, m_bits, k = load_bloom(bloom_path, meta_path)
    print("\n> [Proof] Executing proof-of-concept:")
    if bloom_contains(bitarray_, m_bits, k, POC_ADDRESS.lower()) and \
       search_address_in_file(POC_ADDRESS, addr_file):
        print(f"> [Proof] SUCCESS! PoC Seed: \"{POC_SEED}\" → {POC_ADDRESS}")
    else:
        print("> [Proof] FAILURE!")

    # 4) Launch worker processes
    queue = multiprocessing.Queue()
    proc_count = multiprocessing.cpu_count()
    bloom_params = (bloom_path, meta_path)

    processes = []
    for _ in range(proc_count):
        p = multiprocessing.Process(
            target=worker_process,
            args=(bloom_params, addr_file, queue)
        )
        p.start()
        processes.append(p)

    total = 0
    last = time.time()

    # 5) Collect and print worker messages
    while True:
        try:
            msg = queue.get(timeout=3)
            print(msg)
            if "generated." in msg:
                total += 1000
                print(f"Approximate total generated: {total}")
            if "Collision found!" in msg:
                print("### REAL COLLISION DETECTED! ###")
                break
        except Exception:
            if time.time() - last >= 10:
                print(f"Waiting... ~{total} seeds generated so far")
                last = time.time()

    # 6) Clean up
    for p in processes:
        p.terminate()
        p.join()

if __name__ == "__main__":
    main()
