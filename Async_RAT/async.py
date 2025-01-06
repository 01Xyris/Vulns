# Thanks! https://axmahr.github.io/posts/asyncrat-detection/
import socket
import ssl
import gzip
import msgpack
import random
import threading
import time
from rich.live import Live
from rich.table import Table
from rich.console import Console
from rich import box
import argparse

console = Console()
thread_status = {}
status_lock = threading.Lock()
running = True


def random_chinese_string(length):
    return "".join(chr(random.randint(0x4E00, 0x9FFF)) for _ in range(length))


def update_status(thread_id, status):
    with status_lock:
        thread_status[thread_id] = status


def generate_table():
    table = Table(
        title="Thread Connection Monitor",
        title_style="bold blue",
        box=box.SIMPLE_HEAVY,
        header_style="bold cyan",
        border_style="blue",
    )
    table.add_column("Thread ID", style="cyan", justify="center", width=15)
    table.add_column("Status", style="cyan", justify="center", width=15)

    with status_lock:
        for tid, status in thread_status.items():
            style = "green" if status == "Connected" else "red"
            table.add_row(f"{tid}", f"[{style}]{status}")

    return table


def client_thread(server_ip, server_port, thread_id):
    while running:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
            context.set_ciphers("DEFAULT:@SECLEVEL=0")
            context.verify_mode = ssl.CERT_NONE
            wrapped_socket = context.wrap_socket(sock)

            wrapped_socket.connect((server_ip, server_port))
            update_status(thread_id, "Connected")

            while running:
                random_data = random_chinese_string(random.randint(10, 50))
                client_info = {
                    b"Packet": b"ClientInfo",
                    b"HWID": random_chinese_string(2000).encode("utf-8"),
                    b"User": random_data.encode("utf-8"),
                    b"OS": random_chinese_string(2000).encode("utf-8"),
                    b"Path": random_chinese_string(2000).encode("utf-8"),
                    b"Version": random_chinese_string(2000).encode("utf-8"),
                    b"Admin": random_chinese_string(2000).encode("utf-8"),
                    b"Performance": random_chinese_string(2000).encode("utf-8"),
                    b"Pastebin": random_chinese_string(2000).encode("utf-8"),
                    b"Antivirus": random_chinese_string(2000).encode("utf-8"),
                    b"Installed": random_chinese_string(2000).encode("utf-8"),
                    b"Pong": random_chinese_string(2000).encode("utf-8"),
                    b"Group": random_chinese_string(2000).encode("utf-8"),
                }

                payload = gzip.compress(msgpack.packb(client_info))
                payload_header = len(payload).to_bytes(4, "little")
                full_packet = len(payload_header + payload).to_bytes(4, "little") + payload_header + payload

                wrapped_socket.send(full_packet)


        except Exception:
            update_status(thread_id, "Disconnected")
   
        finally:
            wrapped_socket.close()


def spawn_threads(server_ip, server_port, num_threads):
    threads = []
    for i in range(1, num_threads + 1):
        thread_id = f"Thread {i}"
        update_status(thread_id, "Disconnected")
        thread = threading.Thread(target=client_thread, args=(server_ip, server_port, thread_id))
        thread.daemon = True
        threads.append(thread)
        thread.start()
    return threads


def main(server_ip, server_port, num_threads):
    with Live(generate_table(), refresh_per_second=2) as live:
        spawn_threads(server_ip, server_port, num_threads)
        while running:
            live.update(generate_table())
            time.sleep(0.5)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Thread Connection Monitor")
    parser.add_argument("-ip", required=True, help="Server IP address")
    parser.add_argument("-port", required=True, type=int, help="Server port")
    parser.add_argument("-threads", required=True, type=int, help="Number of threads to simulate")
    args = parser.parse_args()

    console.print("[blue]Starting Connection Monitor...")
    try:
        main(args.ip, args.port, args.threads)
    except KeyboardInterrupt:
        console.print("[yellow]Exiting...")
        running = False mach requirements.txt 