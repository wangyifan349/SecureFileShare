import socket
import threading
import os
import hashlib
import json

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# 分享目录（可自定义）
SHARE_DIR = './share'
# 传输最大块大小
CHUNK_SIZE = 1024 * 512

# 计算单个文件sha256哈希
def calc_file_hash(filepath):
    hasher = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()

# 构建所有可分享文件的信息列表
def build_file_list():
    file_list = []
    for fname in os.listdir(SHARE_DIR):
        path = os.path.join(SHARE_DIR, fname)
        if os.path.isfile(path):
            # 获取文件大小
            size = os.path.getsize(path)
            # 获取hash
            hashcode = calc_file_hash(path)
            # 普通append
            file_info = {}
            file_info['name'] = fname
            file_info['size'] = size
            file_info['hash'] = hashcode
            file_list.append(file_info)
    return file_list

# 发送一段加密的数据（自带nonce、长度信息）
def send_encrypted(client, key, plaintext):
    aesgcm = AESGCM(key)
    # 12字节随机数
    nonce = os.urandom(12)
    # 加密数据
    ct = aesgcm.encrypt(nonce, plaintext, None)
    # 发送长度、nonce、密文
    client.sendall(len(ct).to_bytes(4, 'big'))
    client.sendall(nonce)
    client.sendall(ct)

# 接收一段加密数据
def recv_encrypted(client, key):
    # 读取密文长度
    length_bytes = client.recv(4)
    if len(length_bytes) < 4:
        raise Exception("未能接收完整长度")
    length = int.from_bytes(length_bytes, 'big')
    nonce = client.recv(12)
    if len(nonce) < 12:
        raise Exception("未能接收完整nonce")
    # 分块读取密文
    ct = b''
    nread = 0
    while nread < length:
        chunk = client.recv(length - nread)
        if not chunk:
            raise Exception("密文接收中断")
        ct += chunk
        nread += len(chunk)
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ct, None)
    return plaintext

# 发送加密的文件内容（分块，每块加密/发送）
def send_file_encrypted(client, key, filepath):
    aesgcm = AESGCM(key)
    with open(filepath, 'rb') as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            nonce = os.urandom(12)
            ct = aesgcm.encrypt(nonce, chunk, None)
            # 分别发送长度、nonce、密文
            client.sendall(len(ct).to_bytes(4, 'big'))
            client.sendall(nonce)
            client.sendall(ct)

# 与客户端进行X25519公钥协商
def do_key_exchange(client):
    # 服务端生成密钥对
    sv_private = X25519PrivateKey.generate()
    sv_public = sv_private.public_key().public_bytes()
    # 先发送自己的公钥
    client.sendall(sv_public)
    # 再接收对方公钥
    cli_public_bytes = client.recv(32)
    if len(cli_public_bytes) != 32:
        raise Exception("客户端公钥长度异常")
    cli_public = X25519PublicKey.from_public_bytes(cli_public_bytes)
    # 生成对称密钥（32字节）
    shared_key = sv_private.exchange(cli_public)
    return shared_key

# 为每个客户端连接单独服务（多线程）
def handle_client(client, addr):
    print(f"[+] 与客户端 {addr} 建立新连接")
    try:
        # 密钥协商
        key = do_key_exchange(client)
        # 接收（解密）请求
        req = recv_encrypted(client, key)
        plain_req = req.decode().strip()
        if plain_req == "LIST":
            # 列出所有文件
            file_list = build_file_list()
            response = json.dumps(file_list).encode()
            send_encrypted(client, key, response)
        elif plain_req.startswith("GET "):
            # 下载单个文件
            hash_query = plain_req[4:].strip()
            found = False
            files = build_file_list()
            for fileinfo in files:
                if fileinfo['hash'] == hash_query:
                    fname = fileinfo['name']
                    size = fileinfo['size']
                    meta_json = {}
                    meta_json['name'] = fname
                    meta_json['size'] = size
                    # 发送文件元信息
                    send_encrypted(client, key, json.dumps(meta_json).encode())
                    # 发送文件内容
                    filepath = os.path.join(SHARE_DIR, fname)
                    send_file_encrypted(client, key, filepath)
                    print(f"[+] 已发送文件 {fname} 给 {addr}")
                    found = True
                    break
            if not found:
                send_encrypted(client, key, b"ERR: File Not Found")
        else:
            send_encrypted(client, key, b"ERR: Unknown request")
    except Exception as e:
        print(f"[-] 连接 {addr} 处理异常:", str(e))
    finally:
        client.close()
        print(f"[=] 关闭与 {addr} 的连接")

def main():
    # 确保分享目录存在
    if not os.path.exists(SHARE_DIR):
        os.makedirs(SHARE_DIR)
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # 允许端口复用，避免重启时Address already in use
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', 5002))
    server.listen(8)
    print("【P2P安全文件分享服务】已启动，监听5002端口")
    print("请将要分享的文件放在 share/ 目录下 ...")
    while True:
        client, addr = server.accept()
        t = threading.Thread(target=handle_client, args=(client, addr))
        t.daemon = True
        t.start()

if __name__ == '__main__':
    main()
