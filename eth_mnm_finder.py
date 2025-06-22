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
from rich.prompt import Prompt

# =====================================================================
# ETH-HUNTER v2.1 (Modern UI - EN)
# Searches for Ethereum keys in a large set of addresses
# using a Bloom filter for optimization.
# Reuses existing Bloom filter if present, skips PoC on reuse,
# prompts to keep/delete filter files upon exit.
# =====================================================================

# Proof-of-Concept (PoC) Constants
POC_SEED    = "riot sail ask school orphan tilt analyst dream gun shop mutual leader"
POC_ADDRESS = "0x885becad3144016b140d3adf8f78c9001db64e2a"

console = Console()

# ---------------------------------------------------------------------
# Bloom filter routines
# ---------------------------------------------------------------------

def build_bloom(addr_file: str, bloom_path: str, meta_path: str, false_positive_rate: float = 1e-6):
    console.print(Panel("[bold yellow]Building the Bloom Filter...[/bold yellow]", title="Setup", border_style="yellow"))
    with open(addr_file, 'r') as f:
        n = sum(1 for _ in f)
    m_bits  = math.ceil(-n * math.log(false_positive_rate) / (math.log(2)**2))
    m_bytes = (m_bits + 7) // 8
    k       = max(1, round((m_bits / n) * math.log(2)))
    info = Table(show_header=False, box=None, padding=(0,2))
    info.add_column(style="cyan")
    info.add_column(style="white")
    info.add_row("Addresses to process:", f"{n:,}")
    info.add_row("False positive rate:", f"{false_positive_rate}")
    info.add_row("Filter size (bits):", f"{m_bits:,}")
    info.add_row("Hash functions (k):", f"{k}")
    console.print(Panel(info, title="[bold]Filter Parameters[/bold]", border_style="cyan"))
    bitarray = bytearray(m_bytes)
    with Progress(TextColumn("{task.description}"), BarColumn(), TextColumn("{task.percentage:>3.0f}%"), console=console) as prog:
        task = prog.add_task("Processing addresses...", total=n)
        with open(addr_file, 'r') as f:
            for line in f:
                addr = line.strip().lower()
                if not addr.startswith("0x"):
                    addr = "0x" + addr
                for i in range(k):
                    digest = hashlib.sha256(addr.encode() + i.to_bytes(2, 'little')).digest()
                    pos = int.from_bytes(digest, 'big') % m_bits
                    bitarray[pos//8] |= (1 << (pos%8))
                prog.update(task, advance=1)
    with open(bloom_path, 'wb') as bf:
        bf.write(bitarray)
    with open(meta_path, 'w') as mf:
        json.dump({"m_bits": m_bits, "k": k}, mf)
    console.print(Panel("[bold green]✔ Bloom filter built and saved successfully![/bold green]", border_style="green"))

def load_bloom(bloom_path: str, meta_path: str):
    with open(meta_path, 'r') as mf:
        meta = json.load(mf)
    with open(bloom_path, 'rb') as bf:
        bitarray = bytearray(bf.read())
    return bitarray, meta["m_bits"], meta["k"]

def bloom_contains(bitarray: bytearray, m_bits: int, k: int, address: str) -> bool:
    for i in range(k):
        digest = hashlib.sha256(address.encode() + i.to_bytes(2, 'little')).digest()
        pos = int.from_bytes(digest, 'big') % m_bits
        if not (bitarray[pos//8] & (1 << (pos%8))):
            return False
    return True

def generate_eth_keys(mnemonic_phrase: str, index: int = 0):
    seed   = Mnemonic("english").to_seed(mnemonic_phrase)
    master = BIP32Key.fromEntropy(seed)
    key    = master.ChildKey(44|0x80000000)\
                    .ChildKey(60|0x80000000)\
                    .ChildKey(0|0x80000000)\
                    .ChildKey(0)\
                    .ChildKey(index)
    priv   = key.PrivateKey()
    signing_key = SigningKey.from_string(priv, curve=SECP256k1)
    pub    = b"\x04" + signing_key.get_verifying_key().to_string()
    addr   = "0x" + keccak(pub[1:])[-20:].hex()
    return binascii.hexlify(priv).decode(), addr

def search_address_in_file(address: str, addr_file: str) -> bool:
    with open(addr_file, 'r') as f:
        for line in f:
            a = line.strip().lower()
            if not a.startswith("0x"):
                a = "0x" + a
            if a == address.lower():
                return True
    return False

def get_mnemonic_phrase() -> str:
    return Mnemonic("english").to_mnemonic(os.urandom(16))

def worker_process(bloom_params: tuple, addr_file: str, queue: multiprocessing.Queue, worker_id: int):
    bitarray, m_bits, k = load_bloom(*bloom_params)
    queue.put(("status", worker_id, "Started."))
    count = 0
    while True:
        mnemonic = get_mnemonic_phrase()
        _, address = generate_eth_keys(mnemonic)
        count += 1
        if bloom_contains(bitarray, m_bits, k, address):
            queue.put(("potential_collision", worker_id, mnemonic, address))
        if count % 1000 == 0:
            queue.put(("progress", count, worker_id, mnemonic, address))
            count = 0

# =====================================================================
# UI & Main
# =====================================================================

def make_layout() -> Layout:
    layout = Layout(name="root")
    layout.split(
        Layout(name="header", size=5),
        Layout(ratio=1, name="main"),
        Layout(size=5, name="footer"),
    )
    layout["main"].split_row(
        Layout(name="side"),
        Layout(name="body", ratio=2, minimum_size=60),
    )
    layout["side"].split(
        Layout(name="stats"),
        Layout(name="found"),
    )
    layout["body"].split(
        Layout(name="event_log"),
        Layout(name="latest_keys_log"),
    )
    return layout

def get_header() -> Panel:
    banner = r"""
 _____ _____ _   _   _____ _           _           
| ____|_   _| | | | |  ___(_)_ __   __| | ___ _ __ 
|  _|   | | | |_| | | |_  | | '_ \ / _` |/ _ \ '__|
| |___  | | |  _  | |  _| | | | | | (_| |  __/ |   
|_____| |_| |_| |_| |_|   |_|_| |_|\__,_|\___|_|   
"""
    return Panel(Align.center(Text(banner, style="magenta")), border_style="magenta")

class AppState:
    def __init__(self, num_workers):
        self.num_workers    = num_workers
        self.start_time     = time.time()
        self.total_checked  = 0
        self.keys_per_sec   = 0

        self.found_table = Table(
            title="[bold green]Collisions Found[/bold green]",
            expand=True, border_style="green"
        )
        self.found_table.add_column("Worker", style="dim", width=8)
        self.found_table.add_column("Address", style="cyan", no_wrap=True)
        self.found_table.add_column("Mnemonic Phrase", style="white")

        self.log_messages = deque(maxlen=10)
        self.latest_keys  = deque(maxlen=10)
        self.poc_success  = None

    def update_stats_panel(self) -> Panel:
        elapsed = time.time() - self.start_time
        self.keys_per_sec = self.total_checked / elapsed if elapsed > 0 else 0

        tbl = Table(show_header=False, box=None)
        tbl.add_column(style="bold blue")
        tbl.add_column(style="white")
        tbl.add_row("Active Workers:", f"{self.num_workers}")
        tbl.add_row("Elapsed Time:", f"{timedelta(seconds=int(elapsed))}")
        tbl.add_row("Keys/s:", f"{self.keys_per_sec:,.2f}")
        tbl.add_row("Total Checked:", f"{self.total_checked:,}")

        status = "[bold]SEARCHING...[/bold]"
        if self.poc_success is True:
            status = "[bold green]SEARCHING...[/bold green]"
        elif self.poc_success is False:
            status = "[bold red]PoC FAILED[/bold red]"

        return Panel(tbl, title="[bold]Statistics[/bold]", subtitle=status, border_style="blue")

    def add_log(self, msg: str):
        self.log_messages.append(f"[{time.strftime('%H:%M:%S')}] {msg}")

    def get_log_panel(self) -> Panel:
        return Panel("\n".join(self.log_messages), title="[bold]Event Log[/bold]", border_style="yellow")

    def add_latest_key(self, wid, addr, mnem):
        self.latest_keys.append(f"[dim]W{wid}:[/dim] [cyan]{addr}[/cyan] | {mnem}")

    def get_latest_keys_panel(self) -> Panel:
        return Panel("\n".join(self.latest_keys), title="[bold]Latest Keys[/bold]", border_style="white")

    def add_found_key(self, wid, addr, mnem):
        self.found_table.add_row(f"#{wid}", addr, mnem)
        with open("collisions.txt", "a") as f:
            f.write(f"Address: {addr}, Phrase: {mnem}\n")

def main():
    console.print(get_header())
    addr_file  = "addr.txt"
    bloom_path = "bloom.bin"
    meta_path  = "bloom_meta.json"

    bloom_exists = os.path.exists(bloom_path) and os.path.exists(meta_path)
    if bloom_exists:
        console.print(
            Panel("[bold cyan]Existing Bloom filter found. Skipping build and PoC.[/bold cyan]",
                  border_style="cyan")
        )
    else:
        build_bloom(addr_file, bloom_path, meta_path)
        bitarray, m_bits, k = load_bloom(bloom_path, meta_path)
        poc_panel = Panel.fit(
            f"[cyan]Seed:[/cyan] '{POC_SEED}'\n[cyan]Expected Address:[/cyan] {POC_ADDRESS}",
            title="[bold]Proof of Concept Test[/bold]",
            border_style="cyan"
        )
        console.print(poc_panel)
        if bloom_contains(bitarray, m_bits, k, POC_ADDRESS) and search_address_in_file(POC_ADDRESS, addr_file):
            console.print("[bold green]✔ PoC SUCCESS[/bold green]\n")
            # sinaliza sucesso para colorir o status
            AppState(0).poc_success = True
        else:
            console.print("[bold red]❌ PoC FAILED[/bold red]\n")
            choice = Prompt.ask("Delete filter files?", choices=["yes", "no"], default="yes")
            if choice == "yes":
                os.remove(bloom_path)
                os.remove(meta_path)
                console.print("[bold red]Filter files deleted.[/bold red]")
            return

    bitarray, m_bits, k = load_bloom(bloom_path, meta_path)
    state = AppState(num_workers=multiprocessing.cpu_count())
    queue = multiprocessing.Queue()
    for i in range(state.num_workers):
        multiprocessing.Process(
            target=worker_process,
            args=((bloom_path, meta_path), addr_file, queue, i+1)
        ).start()

    layout = make_layout()
    layout["header"].update(get_header())
    layout["found"].update(Panel(state.found_table, title="[bold]Collisions[/bold]", border_style="green"))

    try:
        with Live(layout, screen=True, refresh_per_second=4):
            with Progress(
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("•"),
                TimeRemainingColumn(),
                console=console
            ) as progress_bar:
                progress_bar.add_task("[yellow]Searching for keys...[/yellow]", total=None)
                layout["footer"].update(progress_bar)

                while True:
                    layout["stats"].update(state.update_stats_panel())
                    layout["event_log"].update(state.get_log_panel())
                    layout["latest_keys_log"].update(state.get_latest_keys_panel())

                    while not queue.empty():
                        msg = queue.get()
                        typ, *data = msg
                        if typ == "progress":
                            # data = [count, worker_id, mnemonic, address]
                            count, wid, mnem, addr = data
                            state.total_checked += count
                            state.add_latest_key(wid, addr, mnem)
                        elif typ == "status":
                            wid, text = data
                            state.add_log(f"Worker #{wid}: {text}")
                        elif typ == "potential_collision":
                            wid, mnem, addr = data
                            state.add_log(f"[yellow]Potential collision by W{wid}: {addr}[/yellow]")
                            if search_address_in_file(addr, addr_file):
                                state.add_log(f"[bold green]CONFIRMED collision by W{wid}![/bold green]")
                                state.add_found_key(wid, addr, mnem)
                                layout["found"].update(
                                    Panel(state.found_table, title="[bold]Collisions[/bold]", border_style="green")
                                )
                            else:
                                state.add_log(f"[dim]False positive: {addr[:12]}...[/dim]")

                    time.sleep(0.25)
    except KeyboardInterrupt:
        state.add_log("[bold red]Interrupted. Shutting down...[/bold red]")
    finally:
        choice = Prompt.ask("Keep Bloom filter files?", choices=["yes", "no"], default="yes")
        if choice == "no":
            if os.path.exists(bloom_path): os.remove(bloom_path)
            if os.path.exists(meta_path): os.remove(meta_path)
            console.print("[bold red]Filter files deleted.[/bold red]")
        else:
            console.print("[bold green]Filter files retained.[/bold green]")
        console.print(Panel("[bold]Exiting program.[/bold]", border_style="dim"))

if __name__ == "__main__":
    main()
