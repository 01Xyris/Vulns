# XWorm Tools: CatFlood Stress Test and Packet Analyzer

## Summary

### CatFlood
Simulates a high-traffic stress test targeting XWorm's remote desktop functionality. The script sends encrypted data, such as an image (e.g., a cat picture), over multiple threads to evaluate XWorm's performance under load.

### Packet Analyzer
Captures, decrypts, and analyzes network packets related to XWorm communications. Useful for understanding traffic patterns and identifying vulnerabilities in encrypted payloads.

---

## Usage

### CatFlood

#### Customize Parameters:
- **`ip`**: Target XWorm-controlled system's IP.
- **`port`**: Target port for communication.
- **`key`**: Encryption key for packet data.
- **`file`**: Path to the image file (e.g., `cat.png`) to send.
- **`threads`**: Number of threads to simulate simultaneous connections.

#### Run the Script:
Execute in a Python environment. Customize parameters as needed.

#### Result:
- Sends encrypted image data in simulated XWorm packets.
- Utilizes multiple threads to stress test the remote desktop feature.

**Example Command**:
```bash
python catflood.py -ip 192.168.1.100 -port 7000 -key "abc123456" -file ./cat.png -threads 10
```
![xra](https://github.com/user-attachments/assets/081a79e4-db3d-4e95-b4a4-08bf6cd1d862)


![Screenshot 2025-01-02 235216](https://github.com/user-attachments/assets/99cccfe4-c1e5-40c2-8795-cf3213104ba2)

---

### Packet Analyzer

#### Customize Parameters:
- **`ip`**: Target IP to filter packets (default: `127.0.0.1`).
- **`port`**: Target port for filtering (default: `7000`).
- **`key`**: Encryption key to decrypt packet payloads.

#### Run the Script:
Execute in a Python environment. Specify the network interface for monitoring.

#### Result:
- Captures TCP packets from the specified IP and port.
- Decrypts and displays packet content along with raw data in a detailed hex dump.

**Example Command**:
```bash
python packet.py -ip 192.168.1.100 -port 7000 -key "abc123456"
```
![packet](https://github.com/user-attachments/assets/b8d01a12-c786-48a4-a513-fd98f29cc8e4)

---

## Requirements

The following Python libraries are required for both tools:

```plaintext
colorama==0.4.6
pycryptodome==3.19.1
rich==13.7.0
scapy==2.4.5
```

Install them using:
```bash
pip install -r requirements.txt
```

