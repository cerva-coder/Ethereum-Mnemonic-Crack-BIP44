# -*- coding: utf-8 -*-
import os
import json
import math
import time
import binascii
import hashlib
import multiprocessing
from datetime import timedelta
from collections import deque

# --- Cryptography Libraries ---
from mnemonic import Mnemonic
from bip32utils import BIP32Key
from ecdsa import SigningKey, SECP256k1
from eth_hash.auto import keccak

# --- Library for Modern Terminal UI ---
from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.live import Live
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn
from rich.table import Table
from rich.align import Align
from rich.text import Text

# ==============================================================================
# 
#  ETH-HUNTER v2.1 (Modern UI - EN)
#  Searches for Ethereum keys in a large set of addresses
#  using a Bloom filter for optimization.
#
# ==============================================================================

# ===== Proof-of-Concept (PoC) Constants =====
POC_SEED = "riot sail ask school orphan tilt analyst dream gun shop mutual leader"
POC_ADDRESS = "0x885becad3144016b140d3adf8f78c9001db64e2a"

# ===== Rich Console Initialization =====
console = Console()

# ==============================================================================
# Core Logic Functions (functionality unchanged)
# ==============================================================================

def ensure_poc(addr_file: str, address: str) -> None:
    """Ensures POC_ADDRESS is the first line of addr.txt."""
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

def build_bloom(addr_file: str, bloom_path: str, meta_path: str, false_positive_rate: float = 1e-6):
    """Builds a Bloom filter from addr.txt with a progress bar."""
    console.print(Panel("[bold yellow]Building the Bloom Filter...[/bold yellow] This might take a few minutes.", title="Setup", border_style="yellow"))
    
    with open(addr_file, 'r') as f:
        n = sum(1 for _ in f)

    m_bits = math.ceil(-n * math.log(false_positive_rate) / (math.log(2) ** 2))
    m_bytes = (m_bits + 7) // 8
    k = max(1, round((m_bits / n) * math.log(2)))

    info_table = Table(show_header=False, box=None, padding=(0, 2))
    info_table.add_column(style="cyan")
    info_table.add_column(style="white")
    info_table.add_row("Addresses to process:", f"{n:,}")
    info_table.add_row("False Positive Rate:", f"{false_positive_rate}")
    info_table.add_row("Filter size (bits):", f"{m_bits:,}")
    info_table.add_row("Hash functions (k):", f"{k}")
    console.print(Panel(info_table, title="[bold]Filter Parameters[/bold]", border_style="cyan"))

    bitarray = bytearray(m_bytes)
    
    with Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        "[progress.percentage]{task.percentage:>3.0f}%",
        console=console
    ) as progress:
        task = progress.add_task("[green]Processing addresses...", total=n)
        with open(addr_file, 'r') as f:
            for line in f:
                addr = line.strip().lower()
                if not addr.startswith("0x"):
                    addr = "0x" + addr
                for i in range(k):
                    digest = hashlib.sha256(addr.encode() + i.to_bytes(2, 'little')).digest()
                    pos = int.from_bytes(digest, 'big') % m_bits
                    bitarray[pos // 8] |= (1 << (pos % 8))
                progress.update(task, advance=1)

    with open(bloom_path, 'wb') as bf:
        bf.write(bitarray)
    with open(meta_path, 'w') as mf:
        json.dump({"m_bits": m_bits, "k": k}, mf)

    console.print(Panel("[bold green]✔ Bloom filter built and saved successfully![/bold green]", border_style="green"))

def load_bloom(bloom_path: str, meta_path: str):
    """Loads the Bloom filter and its metadata from disk."""
    with open(meta_path, 'r') as mf:
        meta = json.load(mf)
    with open(bloom_path, 'rb') as bf:
        bitarray = bytearray(bf.read())
    return bitarray, meta["m_bits"], meta["k"]

def bloom_contains(bitarray: bytearray, m_bits: int, k: int, address: str) -> bool:
    """Checks if an address might be in the Bloom filter."""
    for i in range(k):
        digest = hashlib.sha256(address.encode() + i.to_bytes(2, 'little')).digest()
        pos = int.from_bytes(digest, 'big') % m_bits
        if not (bitarray[pos // 8] & (1 << (pos % 8))):
            return False
    return True

def generate_eth_keys(mnemonic_phrase: str, index: int = 0):
    """Generates an Ethereum private key and address from a mnemonic phrase."""
    seed = Mnemonic("english").to_seed(mnemonic_phrase)
    master = BIP32Key.fromEntropy(seed)
    # BIP44 derivation path for Ethereum: m/44'/60'/0'/0/index
    key = master.ChildKey(44 | 0x80000000).ChildKey(60 | 0x80000000).ChildKey(0 | 0x80000000).ChildKey(0).ChildKey(index)
    
    priv_key_bytes = key.PrivateKey()
    priv_key_hex = binascii.hexlify(priv_key_bytes).decode()
    
    signing_key = SigningKey.from_string(priv_key_bytes, curve=SECP256k1)
    verifying_key = signing_key.get_verifying_key()
    pub_key_bytes = b"\x04" + verifying_key.to_string()
    
    address = "0x" + keccak(pub_key_bytes[1:])[-20:].hex()
    return priv_key_hex, address

def search_address_in_file(address: str, addr_file: str) -> bool:
    """Final check in the original file to confirm a collision."""
    with open(addr_file, 'r') as f:
        for line in f:
            a = line.strip().lower()
            if not a.startswith("0x"):
                a = "0x" + a
            if a == address.lower():
                return True
    return False
    
def get_mnemonic_phrase() -> str:
    """Generates a random 12-word mnemonic phrase."""
    entropy = os.urandom(16) # 128 bits of entropy
    return Mnemonic("english").to_mnemonic(entropy)

def worker_process(bloom_params: tuple, addr_file: str, queue: multiprocessing.Queue, worker_id: int):
    """Worker process that generates and tests keys."""
    bitarray, m_bits, k = load_bloom(*bloom_params)
    
    queue.put(("status", worker_id, "Started and ready to search."))

    count = 0
    while True:
        mnemonic = get_mnemonic_phrase()
        _, address = generate_eth_keys(mnemonic)
        count += 1

        if bloom_contains(bitarray, m_bits, k, address):
            # Potential collision found, send to main for verification
            queue.put(("potential_collision", worker_id, mnemonic, address))
        
        # Report progress in batches to avoid overwhelming the queue
        if count % 1000 == 0:
            queue.put(("progress", count, worker_id, mnemonic, address))
            count = 0

# ==============================================================================
# User Interface (UI) Functions
# ==============================================================================

def make_layout() -> Layout:
    """Defines the visual structure of the dashboard."""
    layout = Layout(name="root")
    layout.split(
        Layout(name="header", size=5),
        Layout(ratio=1, name="main"),
        Layout(size=5, name="footer"),
    )
    layout["main"].split_row(Layout(name="side"), Layout(name="body", ratio=2, minimum_size=60))
    layout["side"].split(Layout(name="stats"), Layout(name="found"))
    # Split the body to accommodate the new "Latest Keys" log
    layout["body"].split(Layout(name="event_log"), Layout(name="latest_keys_log"))
    return layout

def get_header() -> Panel:
    """Creates the header with the title."""
    # ASCII Art remains the same
    banner_text = r"""
 _____ _____ _   _   _____ _           _           
| ____|_   _| | | | |  ___(_)_ __   __| | ___ _ __ 
|  _|   | | | |_| | | |_  | | '_ \ / _` |/ _ \ '__|
| |___  | | |  _  | |  _| | | | | | (_| |  __/ |   
|_____| |_| |_| |_| |_|   |_|_| |_|\__,_|\___|_|   
"""
    title = Text("ETH-HUNTER v2.1", style="bold magenta", justify="center")
    return Panel(Align.center(Text(banner_text, style="magenta"), vertical="middle"), border_style="magenta")

class AppState:
    """A class to manage the application's UI state."""
    def __init__(self, num_workers):
        self.num_workers = num_workers
        self.start_time = time.time()
        self.total_checked = 0
        self.keys_per_second = 0
        
        self.found_keys_table = Table(title="[bold green]Collisions Found[/bold green]", expand=True, border_style="green")
        self.found_keys_table.add_column("Worker", style="dim", width=8)
        self.found_keys_table.add_column("Address", style="cyan", no_wrap=True)
        self.found_keys_table.add_column("Mnemonic Phrase", style="white")
        
        self.log_messages = deque(maxlen=10)
        self.latest_keys = deque(maxlen=10) # For the new panel
        self.poc_success = None

    def update_stats_panel(self) -> Panel:
        """Creates the statistics panel with current data."""
        elapsed_time = time.time() - self.start_time
        self.keys_per_second = self.total_checked / elapsed_time if elapsed_time > 0 else 0
        
        table = Table(show_header=False, box=None)
        table.add_column(style="bold blue")
        table.add_column(style="white")
        table.add_row("Active Workers:", f"{self.num_workers}")
        table.add_row("Elapsed Time:", f"{str(timedelta(seconds=int(elapsed_time)))}")
        table.add_row("Keys/s:", f"{self.keys_per_second:,.2f}")
        table.add_row("Total Checked:", f"{self.total_checked:,}")

        if self.poc_success is True:
            status = "[bold green]PoC SUCCESS[/bold green] | [bold yellow]SEARCHING...[/bold yellow]"
        elif self.poc_success is False:
            status = "[bold red]PoC FAILED[/bold red]"
        else:
            status = "[bold]INITIALIZING...[/bold]"

        return Panel(table, title="[bold]Statistics[/bold]", subtitle=status, border_style="blue")
    
    def add_log(self, message: str):
        self.log_messages.append(f"[{time.strftime('%H:%M:%S')}] {message}")

    def get_log_panel(self) -> Panel:
        log_text = "\n".join(self.log_messages)
        return Panel(log_text, title="[bold]Event Log[/bold]", border_style="yellow")

    def add_latest_key(self, worker_id, address, mnemonic):
        self.latest_keys.append(f"[dim]W{worker_id}:[/dim] [cyan]{address}[/cyan] | {mnemonic}")

    def get_latest_keys_panel(self) -> Panel:
        """Creates the panel to show the latest generated keys."""
        key_text = "\n".join(self.latest_keys)
        return Panel(key_text, title="[bold]Latest Generated Keys[/bold]", border_style="white")

    def add_found_key(self, worker_id, address, mnemonic):
        self.found_keys_table.add_row(f"#{worker_id}", address, mnemonic)
        with open("collisions.txt", "a") as f:
            f.write(f"Address: {address}, Phrase: {mnemonic}\n")

# ==============================================================================
# Main Function
# ==============================================================================

def main():
    """Main function to orchestrate the UI and workers."""
    console.print(get_header())

    addr_file = "addr.txt"
    bloom_path = "bloom.bin"
    meta_path = "bloom_meta.json"

    # 1. Ensure PoC is in the address file
    ensure_poc(addr_file, POC_ADDRESS)

    # 2. Build Bloom filter if it doesn't exist
    if not (os.path.exists(bloom_path) and os.path.exists(meta_path)):
        build_bloom(addr_file, bloom_path, meta_path)
    
    # 3. Load filter and run PoC test
    bitarray, m_bits, k = load_bloom(bloom_path, meta_path)
    
    app_state = AppState(num_workers=multiprocessing.cpu_count())

    poc_panel = Panel.fit(
        f"[cyan]Seed:[/cyan] '{POC_SEED}'\n[cyan]Expected Address:[/cyan] {POC_ADDRESS}",
        title="[bold]Proof of Concept (PoC) Test[/bold]",
        border_style="cyan"
    )
    console.print(poc_panel)

    if bloom_contains(bitarray, m_bits, k, POC_ADDRESS.lower()) and search_address_in_file(POC_ADDRESS, addr_file):
        console.print("[bold green]✔ SUCCESS: Proof of concept works as expected.[/bold green]\n")
        app_state.poc_success = True
    else:
        console.print("[bold red]❌ FAILURE: Proof of concept failed. Check your seed or address file.[/bold red]\n")
        app_state.poc_success = False
        return

    # 4. Launch worker processes
    queue = multiprocessing.Queue()
    proc_count = multiprocessing.cpu_count()
    bloom_params = (bloom_path, meta_path)
    processes = []
    for i in range(proc_count):
        p = multiprocessing.Process(target=worker_process, args=(bloom_params, addr_file, queue, i + 1))
        p.start()
        processes.append(p)

    # 5. Start the UI with Rich Live
    layout = make_layout()
    layout["header"].update(get_header())
    layout["found"].update(Panel(app_state.found_keys_table, title="[bold]Collisions[/bold]", border_style="green"))

    with Live(layout, screen=True, redirect_stderr=False, refresh_per_second=4) as live:
        try:
            with Progress(
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("•"),
                TimeRemainingColumn(),
                console=console
            ) as progress_bar:
                search_task = progress_bar.add_task("[yellow]Searching for keys...", total=None)
                layout["footer"].update(progress_bar)
                
                while True:
                    # Update all UI panels in the loop
                    layout["stats"].update(app_state.update_stats_panel())
                    layout["event_log"].update(app_state.get_log_panel())
                    layout["latest_keys_log"].update(app_state.get_latest_keys_panel())
                    
                    while not queue.empty():
                        msg = queue.get()
                        msg_type, *payload = msg
                        
                        if msg_type == "progress":
                            count, worker_id, mnemonic, address = payload
                            app_state.total_checked += count
                            app_state.add_latest_key(worker_id, address, mnemonic)
                        elif msg_type == "status":
                            worker_id, status_msg = payload
                            app_state.add_log(f"[dim]Worker #{worker_id}:[/dim] {status_msg}")
                        elif msg_type == "potential_collision":
                            worker_id, mnemonic, address = payload
                            app_state.add_log(f"[yellow]Worker #{worker_id} found a POTENTIAL collision! Verifying...[/yellow]")
                            if search_address_in_file(address, addr_file):
                                app_state.add_log(f"[bold green]CONFIRMED! Worker #{worker_id} found a real collision![/bold green]")
                                app_state.add_found_key(worker_id, address, mnemonic)
                                layout["found"].update(Panel(app_state.found_keys_table, title="[bold]Collisions[/bold]", border_style="green"))
                            else:
                                app_state.add_log(f"[dim]Worker #{worker_id}: False positive for address {address[:12]}...[/dim]")
                    
                    time.sleep(0.25)

        except KeyboardInterrupt:
            app_state.add_log("[bold red]Manual interruption detected. Shutting down workers...[/bold red]")
            live.update(layout) # Update one last time

        finally:
            # 6. Cleanup
            for p in processes:
                p.terminate()
                p.join()
            console.print(Panel("[bold]Processes terminated. Exiting program.[/bold]", border_style="dim"))


if __name__ == "__main__":
    main()