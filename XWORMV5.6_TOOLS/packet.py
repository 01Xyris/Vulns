from scapy.all import sniff, get_if_list, TCP, Raw
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import hashlib
import argparse
from colorama import init, Fore, Style

init()

BANNER = f"""
{Fore.CYAN}╔═══════════════════════════════════════╗
║        XWorm Packet Analyzer          ║
╚═══════════════════════════════════════╝{Style.RESET_ALL}
"""

def decrypt_data(data, key):
    try:
        hashed_key = hashlib.md5(key.encode()).digest()
        cipher = AES.new(hashed_key, AES.MODE_ECB)
        return unpad(cipher.decrypt(data), AES.block_size)
    except:
        return b''

def format_hex_dump(data):
    output = []
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_line = ' '.join(f'{b:02x}' for b in chunk)
        ascii_line = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
        line = f"{Fore.YELLOW}{i:04x}{Style.RESET_ALL}  {Fore.CYAN}{hex_line:<48}{Style.RESET_ALL}  {Fore.GREEN}|{ascii_line}|{Style.RESET_ALL}"
        output.append(line)
    return '\n'.join(output)

def select_interface():
    interfaces = get_if_list()
    print(f"{Fore.CYAN}Available interfaces:{Style.RESET_ALL}")
    for i, iface in enumerate(interfaces):
        print(f"{Fore.GREEN}{i}{Style.RESET_ALL}: {iface}")
    
    while True:
        try:
            choice = int(input(f"{Fore.YELLOW}Select interface number: {Style.RESET_ALL}"))
            if 0 <= choice < len(interfaces):
                return interfaces[choice]
            print(f"{Fore.RED}Invalid choice{Style.RESET_ALL}")
        except ValueError:
            print(f"{Fore.RED}Please enter a number{Style.RESET_ALL}")

def handle_packet(packet, ip, port, key, logfile):
    if not (TCP in packet and packet[TCP].dport == port):
        return

    if ip != "127.0.0.1" and packet[IP].dst != ip:
        return

    if Raw not in packet:
        return

    payload = bytes(packet[Raw])
    try:
        null_pos = payload.index(b'\0')
        encrypted_data = payload[null_pos+1:]
        
        if not encrypted_data:
            return

        decrypted = decrypt_data(encrypted_data, key)
        if not decrypted:
            return

        packet_info = f"""
{Fore.GREEN}=== XWorm Packet ==={Style.RESET_ALL}
{Fore.CYAN}Time: {datetime.fromtimestamp(float(packet.time))}{Style.RESET_ALL}
{Fore.CYAN}Length: {len(packet)}{Style.RESET_ALL}
{Fore.YELLOW}Raw Packet:{Style.RESET_ALL}
"""
        print(packet_info)
        print(format_hex_dump(payload))
        print(f"\n{Fore.GREEN}Decrypted:{Style.RESET_ALL}\n{decrypted.decode()}\n")

        log_entry = f"""
=== XWorm Packet ===
Time: {datetime.fromtimestamp(float(packet.time))}
Length: {len(packet)}
Decrypted: {decrypted.decode()}
Raw Packet (Hex): {payload.hex()}
"""
        logfile.write(log_entry)
        logfile.flush()

    except:
        return

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-ip', default='127.0.0.1', help='Target IP')
    parser.add_argument('-port', type=int, default=7000, help='Target port')
    parser.add_argument('-key', default='<123456789>', help='XWorm key')
    args = parser.parse_args()

    print(BANNER)
    iface = select_interface()
    
    print(f"\n{Fore.GREEN}Starting capture:{Style.RESET_ALL}")
    print(f"Interface: {iface}")
    print(f"Target IP: {args.ip}")
    print(f"Port: {args.port}")
    print(f"Key: {args.key}\n")

    try:
        with open('xworm_packets.txt', 'a') as logfile:
            sniff(
                filter=f"tcp port {args.port}",
                prn=lambda x: handle_packet(x, args.ip, args.port, args.key, logfile),
                store=0,
                iface=iface
            )
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Capture stopped by user{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}Error: {str(e)}{Style.RESET_ALL}")

if __name__ == "__main__":
    main()