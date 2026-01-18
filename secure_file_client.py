"""
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

secure_file_client.py
A secure file sharing client that connects to the secure_file_server.py.
- - Performs X25519+AES-GCM end-to-end encryption.
- - Displays file lists and enables user to download files by index.
- - All messages and file chunks are encrypted over the network.
- - Protocol: [4-byte length][12-byte nonce][ciphertext] for every message/chunk.
- - Persistent session; user can repeatedly list/download/quit.
-----BEGIN PGP SIGNATURE-----

iQEzBAEBCAAdFiEEx7jstv8+CLBtLmM+Ob1bwvNo5hkFAmls1nIACgkQOb1bwvNo
5hkRZggA01VOdqouSD0VLGh1OAlWzaEYKVUCGMLjxR6QWFVRCYEnY+K/niv93H2I
rQV3UoXxp3aAqjwHReNDCMPzZsUnzQdwZy7T076Tkj/FVpmwLx955Frv86aH157Y
ijZr13ZtJ2BOzXEwiBxSAenzx6RPqgTZcYijhqTByQwtWLaWXp9m0Uq7O/aSZcan
vpl5Ce3D6y+l3piOiMF+S5vvJF2k451wMA7hf3a9vwEugJ9FC5AvnIa0jYfsd/an
JALz/KYcmu7glp/Tha02Sr3/vk359upZGCHindmBUEXMYrc858fGE+hn5ZfyQAQi
OjK1iP1riodSW6yQlxT/Vhbmdy+hNw==
=eh4t
-----END PGP SIGNATURE-----
"""
import socket                                    # For networking
import json                                      # For file lists & metadata
import hashlib                                   # For local hash verification
import os                                        # For file writing/renaming
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization

CHUNK_SIZE = 1024 * 512                          # File download chunk size (512 KiB)

def calculate_file_hash(file_path):
    """
    Compute SHA256 hash for local file.
    Args:
        file_path (str): Path to file.
    Returns:
        str: Hexadecimal SHA256 hash of file contents.
    """
    hasher = hashlib.sha256()
    with open(file_path, 'rb') as file_handle:
        while True:
            chunk = file_handle.read(CHUNK_SIZE)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()

def receive_n_bytes(sock, n):
    """
    Receive exactly n bytes (handles short reads).
    Args:
        sock (socket.socket): Open socket.
        n (int): Number of bytes to receive.
    Returns:
        bytes: Received bytes.
    """
    buffer = b''
    while len(buffer) < n:
        segment = sock.recv(n - len(buffer))
        if not segment:
            raise Exception("Socket closed unexpectedly")
        buffer += segment
    return buffer

def perform_key_exchange(sock):
    """
    Execute X25519 key exchange with server.
    Args:
        sock (socket.socket): Open TCP socket.
    Returns:
        bytes: 32-byte session symmetric key.
    """
    private_key = X25519PrivateKey.generate()                                   # New private key per session
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    server_public_bytes = receive_n_bytes(sock, 32)                             # Receive server's public key
    sock.sendall(public_key)                                                    # Send client's public key
    server_public_key = X25519PublicKey.from_public_bytes(server_public_bytes)
    session_key = private_key.exchange(server_public_key)
    return session_key

def send_encrypted_message(sock, key, plain_bytes):
    """
    Encrypt data and send using [length][nonce][ciphertext] convention.
    Args:
        sock (socket.socket): Open socket.
        key (bytes): Session key.
        plain_bytes (bytes): Plaintext (command or file data).
    """
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plain_bytes, None)
    sock.sendall(len(ciphertext).to_bytes(4, 'big'))                            # Length
    sock.sendall(nonce)                                                         # Nonce
    sock.sendall(ciphertext)                                                    # Data

def receive_encrypted_message(sock, key):
    """
    Receive and decrypt a message or data chunk from server.
    Args:
        sock (socket.socket): Open socket.
        key (bytes): Session key.
    Returns:
        bytes: Plain data from server.
    """
    length_bytes = receive_n_bytes(sock, 4)
    msg_length = int.from_bytes(length_bytes, 'big')
    nonce = receive_n_bytes(sock, 12)
    ciphertext = receive_n_bytes(sock, msg_length)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)

def print_file_list(file_list):
    """
    Print a formatted file list (index, name, size, hash) to user.
    Args:
        file_list (list): List of file info dicts.
    """
    print("Available files on server:")
    for index in range(len(file_list)):
        file_info = file_list[index]
        print(f"{index+1}. {file_info['name']} ({file_info['size']} bytes)  hash: {file_info['hash']}")

def main():
    """
    Main client loop. 
    Handles connection, menu, commands, file downloads, and orderly quit.
    """
    server_ip = input("Enter server IP: ").strip()
    while True:                                                                     # Entire client app loop
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((server_ip, 5002))
        key = perform_key_exchange(sock)                                            # Get session key
        while True:                                                                 # Session loop
            print("\n1. List files on server")
            print("2. Download file")
            print("3. Quit")
            action = input("Choose action [1/2/3]: ").strip()
            if action == "1":
                send_encrypted_message(sock, key, b"LIST")                          # Send list command
                data = receive_encrypted_message(sock, key)
                file_list = json.loads(data.decode())
                print_file_list(file_list)
            elif action == "2":
                send_encrypted_message(sock, key, b"LIST")                          # Always get fresh list
                data = receive_encrypted_message(sock, key)
                file_list = json.loads(data.decode())
                print_file_list(file_list)
                selection = input("Select file number to download (or Enter to cancel): ").strip()
                if not selection:
                    continue                                                        # User cancelled
                index = int(selection) - 1
                if index < 0 or index >= len(file_list):
                    print("Invalid file number.")
                    continue
                file_hash_code = file_list[index]['hash']
                request = "GET " + file_hash_code
                send_encrypted_message(sock, key, request.encode())                  # Request file by hash
                meta_bytes = receive_encrypted_message(sock, key)
                try:
                    meta_info = json.loads(meta_bytes)                              # Expect meta info JSON
                    file_name = meta_info["name"]
                    file_size = meta_info["size"]
                except Exception:
                    print("Could not retrieve file metadata.")
                    continue
                print(f"Downloading: {file_name} ({file_size} bytes)")
                with open(file_name, 'wb') as file_handle:
                    received_size = 0
                    aesgcm = AESGCM(key)
                    while received_size < file_size:                                # Download loop
                        length_bytes = receive_n_bytes(sock, 4)
                        chunk_length = int.from_bytes(length_bytes, 'big')
                        nonce = receive_n_bytes(sock, 12)
                        ciphertext = receive_n_bytes(sock, chunk_length)
                        chunk_plain = aesgcm.decrypt(nonce, ciphertext, None)
                        file_handle.write(chunk_plain)
                        received_size += len(chunk_plain)
                        print(f"\rReceived {received_size} / {file_size} bytes", end="", flush=True)
                print()
                print("Download complete. Verifying hash...")
                calculated_hash = calculate_file_hash(file_name)
                if calculated_hash == file_hash_code:
                    print(f"Hash verified! ({calculated_hash})")
                else:
                    print("Hash mismatch!")
                    os.rename(file_name, file_name + ".broken")
                    print(f"File renamed to {file_name}.broken")
            elif action == "3":
                send_encrypted_message(sock, key, b"QUIT")                          # Send session close
                sock.close()                                                        # Graceful shutdown
                print("Goodbye.")
                return
            else:
                print("Invalid input.")
        sock.close()                                                                # (Session end not reached)
if __name__ == '__main__':
    main()
