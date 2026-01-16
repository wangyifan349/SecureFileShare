
# SecureFileShare

SecureFileShare is a lightweight, secure direct file sharing tool. It allows you to safely share files with others over the network, using modern encryption, without reliance on cloud services or third-party servers. The tool offers directory access with file integrity verification and strong end-to-end encryption for all data.

## Features

- **End-to-End Encryption:** Every connection uses X25519 (Curve25519) for key exchange. All commands, metadata, and file contents are protected using AES-256-GCM encryption—no clear data is ever transmitted.
- **Directory Listing with Hashes:** Users can securely browse the server’s shared directory, seeing filenames, sizes, and SHA-256 hashes which are used for file integrity checks.
- **Safe File Downloads:** Files are downloaded in encrypted chunks and automatically verified after transfer. Corrupted or tampered files are detected via SHA-256 hashing.
- **Concurrent Users:** The server can handle several users at once, providing robust multi-client support.
- **Cross-Platform & Minimal Dependencies:** Runs everywhere with Python 3.6+ and only requires the `cryptography` module.
- **No Central Server Needed:** All sharing is performed directly between the two endpoints, keeping your files private.

## How It Works

After a client connects, both sides securely negotiate a shared secret via X25519 key exchange. All subsequent communications (directory requests, file transfers) are encrypted with AES-256-GCM using this secret. Users can browse available files, select a file by its displayed hash, and download it directly and securely. After download, the client re-calculates the SHA-256 hash to ensure file integrity.

## Installation

**Requirements:**  
- Python 3.6 or newer  
- `cryptography` Python package (`pip install cryptography`)

**Download the code:**  
```bash
git clone https://github.com/wangyifan349/SecureFileShare.git
cd SecureFileShare
```

## Usage

### As the Server

1. Copy files you want to share into the `share/` directory (create the folder if it doesn’t exist).
2. Start the server with:
   ```bash
   python file_share_server.py
   ```
   The server will listen on port 5002 by default. For sharing beyond your local network, make sure to open/forward this port as needed.

### As the Client

1. Start the client script:
   ```bash
   python file_share_client.py
   ```
2. Enter the server IP address when prompted. You may list files available for sharing and select any file to download by its index.
3. The tool will verify downloaded files automatically using their SHA-256 hash.

## Security Considerations

All transferred data is protected by modern cryptographic algorithms. However, endpoint authentication (e.g., certificate pinning or public key fingerprint verification) is not included. This means that while data is unreadable to passive attackers, a fully active man-in-the-middle attacker could theoretically impersonate a user if they intercept the connection at setup. For trusted networks and personal use, this provides strong privacy and security.

## Limitations

- No automatic detection or traversal of network boundaries; both server and client must be network-accessible to each other.
- One-way file sharing only (no uploads from clients by design).
- Command line only; no graphical interface.
- No support for pausing or resuming interrupted file transfers.
- Not designed for sharing with large numbers of unknown users.

## Roadmap

- support for verifying peer identities through key fingerprint confirmation
- resume/download interruption handling
- GUI front-end
- simple authentication/whitelisting for incoming connections

## License

Distributed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Author

Maintained by [@wangyifan349](https://github.com/wangyifan349)

---

**Disclaimer:**  
SecureFileShare is intended for personal, educational, or research use. Always observe local laws and security risks when sharing or receiving files over a network.

gnore` or want further tweaks—just let me know!
