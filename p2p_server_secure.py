"""
secure_file_server.py

A secure multi-threaded file sharing server using X25519 key exchange (ECDH) and AES-GCM symmetric encryption.
- Shares files in the './share' directory.
- Handles multiple clients concurrently (thread per client).
- Each client connection is persistent until 'QUIT' command.
- All interactions ("LIST", "GET <hash>", file transfers) are fully encrypted blockwise.
- Network protocol: All messages are [4-byte length][12-byte nonce][ciphertext].
- Tested with Python 3, cryptography (pip install cryptography).

Author: (Your Name)
Date: (YYYY-MM-DD)
"""

import socket                                  # Network communications
import threading                               # For concurrent clients
import os                                      # File and path operations
import hashlib                                 # For SHA256 hashes
import json                                    # For encoding/decoding file lists/metadata
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization

SHARE_DIRECTORY = './share'                    # Path for shared files
CHUNK_SIZE = 1024 * 512                        # Block/chunk size for file transfer (512 KiB)

def calculate_file_hash(file_path):
    """
    Calculate SHA256 hash of a file.
    Args:
        file_path (str): Full file path.
    Returns:
        str: Hexadecimal hash.
    """
    hasher = hashlib.sha256()                  # Create a new SHA256 object
    with open(file_path, 'rb') as file_handle:
        while True:
            chunk = file_handle.read(CHUNK_SIZE)       # Read in chunks
            if not chunk:
                break
            hasher.update(chunk)                       # Hash chunk
    return hasher.hexdigest()                  # Get hash as hex string

def collect_file_list():
    """
    Gather all regular files in the share directory, with their sizes and hashes.
    Returns:
        list: List of dicts with 'name', 'size', 'hash' per file.
    """
    file_list = []
    for file_name in os.listdir(SHARE_DIRECTORY):                       # Walk all files in share dir
        full_path = os.path.join(SHARE_DIRECTORY, file_name)            # Full path
        if os.path.isfile(full_path):                                   # Only regular files
            file_size = os.path.getsize(full_path)                      # Get file size in bytes
            file_hash = calculate_file_hash(full_path)                  # Compute file hash
            file_info = {}                                             # Dict for file attributes
            file_info['name'] = file_name                               # File name only, not path
            file_info['size'] = file_size                               # File size
            file_info['hash'] = file_hash                               # SHA256 hash
            file_list.append(file_info)                                 # Add to result list
    return file_list

def send_encrypted_message(sock, key, plain_bytes):
    """
    Encrypts a message and sends it over the socket using: [length][nonce][ciphertext].
    Args:
        sock (socket.socket): Connected socket object.
        key (bytes): 32-byte symmetric key (from key exchange).
        plain_bytes (bytes): Data to encrypt and send.
    """
    aesgcm = AESGCM(key)                                               # AES-GCM object with the session key
    nonce = os.urandom(12)                                             # Generate 12-byte random nonce
    ciphertext = aesgcm.encrypt(nonce, plain_bytes, None)              # Encrypt plaintext
    sock.sendall(len(ciphertext).to_bytes(4, 'big'))                   # Send 4-byte ciphertext length
    sock.sendall(nonce)                                                # Send nonce
    sock.sendall(ciphertext)                                           # Send the actual ciphertext

def receive_n_bytes(sock, n):
    """
    Receive exactly n bytes from socket. Handles TCP stream fragmentation.
    Args:
        sock (socket.socket): Connected socket object.
        n (int): Number of bytes to read.
    Returns:
        bytes: Received bytes.
    """
    buffer = b''                                                      # Empty buffer
    while len(buffer) < n:
        segment = sock.recv(n - len(buffer))                          # Try to read the rest
        if not segment:
            raise Exception("Socket closed unexpectedly")             # If socket closed early
        buffer += segment                                            # Append to buffer
    return buffer

def receive_encrypted_message(sock, key):
    """
    Receives an encrypted message using [length][nonce][ciphertext] protocol and decrypts it.
    Args:
        sock (socket.socket): Connected socket object.
        key (bytes): Session key.
    Returns:
        bytes: Decrypted plain data.
    """
    length_bytes = receive_n_bytes(sock, 4)                           # Get length prefix
    msg_length = int.from_bytes(length_bytes, 'big')                  # Length as int
    nonce = receive_n_bytes(sock, 12)                                 # Always 12 bytes (GCM)
    ciphertext = receive_n_bytes(sock, msg_length)                    # Ciphertext itself
    aesgcm = AESGCM(key)                                              # AES-GCM for decrypt
    plain_bytes = aesgcm.decrypt(nonce, ciphertext, None)             # Decrypt
    return plain_bytes

def send_file(sock, key, file_path):
    """
    Encrypts and sends a file block-wise using the current session key.
    Args:
        sock (socket.socket): Connected socket object.
        key (bytes): Session key.
        file_path (str): Path of the file to transfer.
    """
    aesgcm = AESGCM(key)                                              # AES-GCM for encrypting each chunk
    with open(file_path, 'rb') as file_handle:
        while True:
            chunk = file_handle.read(CHUNK_SIZE)                      # Read chunk
            if not chunk:
                break
            nonce = os.urandom(12)                                    # New nonce per chunk
            ciphertext = aesgcm.encrypt(nonce, chunk, None)           # Encrypt
            sock.sendall(len(ciphertext).to_bytes(4, 'big'))          # Send length of ciphertext
            sock.sendall(nonce)                                       # Send nonce
            sock.sendall(ciphertext)                                  # Send ciphertext

def perform_key_exchange(sock):
    """
    Performs X25519 key exchange. Server sends its public key, receives client's public key,
    and derives the shared symmetric key.
    Args:
        sock (socket.socket): Connected socket object.
    Returns:
        bytes: 32-byte shared session key.
    """
    private_key = X25519PrivateKey.generate()                         # Generate ephemeral private key
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,                          # 'Raw' gives 32 bytes key
        format=serialization.PublicFormat.Raw
    )
    sock.sendall(public_key)                                          # Send server public key to client
    peer_public_bytes = receive_n_bytes(sock, 32)                     # Receive 32 byte client public key
    peer_public_key = X25519PublicKey.from_public_bytes(peer_public_bytes)
    return private_key.exchange(peer_public_key)                      # Return shared secret

def handle_client_connection(sock, address):
    """
    Handles all communication (persistent session) with a single client.
    Args:
        sock (socket.socket): Connected client socket.
        address (tuple): (ip, port) tuple for client.
    """
    print(f"[+] Connection from {address}")                           # Log incoming connections
    key = perform_key_exchange(sock)                                  # Key exchange, get session key
    while True:
        # Main session loop: accept repeated LIST/GET/QUIT
        request_bytes = None
        try:
            request_bytes = receive_encrypted_message(sock, key)      # Read encrypted client request
        except Exception:
            break                                                     # End connection on error (e.g. client disconnected)
        if not request_bytes:
            break
        request = request_bytes.decode().strip()                      # Decode command string
        if request.upper() == "LIST":
            file_list = collect_file_list()                           # Get up-to-date file list
            response_bytes = json.dumps(file_list).encode()           # Encode as JSON
            send_encrypted_message(sock, key, response_bytes)         # Reply with encrypted list
        elif request.upper().startswith("GET "):
            requested_hash = request[4:].strip()                      # Extract requested hash
            file_found = False
            file_list = collect_file_list()                           # Always current
            for file_info in file_list:                               # Loop for match (not in comp)
                if file_info['hash'] == requested_hash:
                    file_name = file_info['name']
                    file_size = file_info['size']
                    meta_info = {}
                    meta_info['name'] = file_name                     # File name for download
                    meta_info['size'] = file_size                     # File size for download
                    send_encrypted_message(sock, key, json.dumps(meta_info).encode())  # Send meta first
                    full_path = os.path.join(SHARE_DIRECTORY, file_name)
                    send_file(sock, key, full_path)                   # Then encrypted file data
                    print(f"[+] Sent file {file_name} to {address}")  # Log file transfer
                    file_found = True
                    break
            if not file_found:                                        # Hash did not match any file
                send_encrypted_message(sock, key, b"ERR: File Not Found")
        elif request.upper() == "QUIT":
            print(f"[=] {address} closed connection")
            break                                                     # End session on client quit
        else:
            send_encrypted_message(sock, key, b"ERR: Unknown request")# Reply to invalid requests
    sock.close()                                                      # Cleanly close connection
    print(f"[=] Connection ended: {address}")                         # Log

def main():
    # Entry point. Prepares directory, starts listener loop, accepts connections, handles each in thread.
    if not os.path.exists(SHARE_DIRECTORY):                           # Create directory if missing
        os.makedirs(SHARE_DIRECTORY)
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # Create TCP socket
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('0.0.0.0', 5002))                             # Listen on all interfaces
    server_socket.listen(8)                                           # Allow up to 8 queued connections
    print("Secure file sharing server started on port 5002")
    print("Place files you want to share in the share/ folder.")
    while True:
        client_socket, client_address = server_socket.accept()        # Wait for a client connection
        thread = threading.Thread(target=handle_client_connection, args=(client_socket, client_address))
        thread.daemon = True                                         # Thread dies with main program
        thread.start()                                               # Start thread per client

if __name__ == '__main__':
    main()
