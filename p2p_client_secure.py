import socket
import json
import hashlib
import os

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

CHUNK_SIZE = 1024 * 512

# 本地计算文件哈希
def file_hash(filepath):
    hasher = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()

# 与服务端进行密钥协商
def do_key_exchange(s):
    # 客户端生成密钥对
    cl_private = X25519PrivateKey.generate()
    cl_public = cl_private.public_key().public_bytes()
    # 先接收服务端公钥
    sv_public_bytes = s.recv(32)
    if len(sv_public_bytes) != 32:
        raise Exception("服务端公钥长度异常")
    # 发送自己的公钥
    s.sendall(cl_public)
    # 生成对称密钥
    sv_public = X25519PublicKey.from_public_bytes(sv_public_bytes)
    shared_key = cl_private.exchange(sv_public)
    return shared_key

# 发送加密数据
def send_encrypted(s, key, plaintext):
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext, None)
    s.sendall(len(ct).to_bytes(4, 'big'))
    s.sendall(nonce)
    s.sendall(ct)

# 接收加密数据
def recv_encrypted(s, key):
    length_bytes = s.recv(4)
    if len(length_bytes) < 4:
        raise Exception("未能接收完整长度")
    length = int.from_bytes(length_bytes, 'big')
    nonce = s.recv(12)
    if len(nonce) < 12:
        raise Exception("未能接收完整nonce")
    ct = b''
    nread = 0
    while nread < length:
        chunk = s.recv(length - nread)
        if not chunk:
            raise Exception("密文接收中断")
        ct += chunk
        nread += len(chunk)
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ct, None)
    return plaintext

# 获取服务器文件列表
def list_files(addr):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((addr, 5002))
    # 密钥交换
    key = do_key_exchange(s)
    # 发请求
    send_encrypted(s, key, b"LIST")
    # 收响应
    data = recv_encrypted(s, key)
    s.close()
    file_list = json.loads(data.decode())
    print("服务器可用文件：")
    idx = 1
    for f in file_list:
        # 打印索引、文件名、大小、哈希
        print("%d. %s (%d bytes)  hash: %s" % (idx, f["name"], f["size"], f["hash"]))
        idx = idx + 1
    return file_list

# 下载文件
def download_file(addr, file_hash_code):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((addr, 5002))
    key = do_key_exchange(s)
    # 发请求
    cmd = "GET " + file_hash_code
    send_encrypted(s, key, cmd.encode())
    # 先收meta
    meta = recv_encrypted(s, key)
    try:
        meta_json = json.loads(meta)
        fname = meta_json["name"]
        size = meta_json["size"]
    except:
        print("无法解析响应元数据，或文件不存在。")
        s.close()
        return
    print("准备下载: %s (%d bytes)" % (fname, size))
    # 下载文件内容
    with open(fname, 'wb') as f:
        recv_size = 0
        aesgcm = AESGCM(key)
        while recv_size < size:
            # 接收4字节长度
            plen_bytes = s.recv(4)
            if not plen_bytes or len(plen_bytes) < 4:
                break
            plen = int.from_bytes(plen_bytes, 'big')
            nonce = s.recv(12)
            if not nonce or len(nonce) < 12:
                break
            ct = b''
            nct = 0
            while nct < plen:
                chunk = s.recv(plen - nct)
                if not chunk:
                    break
                ct += chunk
                nct += len(chunk)
            if nct < plen:
                break
            try:
                chunk_plain = aesgcm.decrypt(nonce, ct, None)
            except Exception as e:
                print("解密失败:", str(e))
                break
            f.write(chunk_plain)
            recv_size += len(chunk_plain)
            print("\r已接收 %d / %d bytes" % (recv_size, size), end="", flush=True)
    s.close()
    print()
    print("下载完成，校验中 ...")
    got_hash = file_hash(fname)
    if got_hash == file_hash_code:
        print("文件校验通过！ (%s)" % got_hash)
    else:
        print("文件校验失败！")
        os.rename(fname, fname + ".broken")
        print("已重命名为 %s.broken" % fname)

def main():
    server_ip = input("请输入服务器IP: ").strip()
    print("1. 列出服务器文件")
    print("2. 下载文件")
    act = input("选择操作[1/2]: ").strip()
    if act == "1":
        list_files(server_ip)
    elif act == "2":
        file_list = list_files(server_ip)
        select = input("选择文件编号下载: ").strip()
        try:
            idx = int(select) - 1
            if idx >= 0 and idx < len(file_list):
                file_hash_code = file_list[idx]['hash']
                download_file(server_ip, file_hash_code)
            else:
                print("编号无效")
        except Exception as e:
            print("输入有误:", str(e))
    else:
        print("无效输入。")

if __name__ == '__main__':
    main()
