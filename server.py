# -*- coding: utf-8 -*-
import socket
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import random
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256

# D-H密钥交换
def DHKeyExchange(p, g):
	a = random.randint(1, p - 1)
	A = pow(g, a, p)
	return A, a

# D-H密钥计算
def DHComputeKey(A, b, p):
	s = pow(A, b, p)
	return hashlib.sha256(str(s)).digest()

# D-H加密
def encrypt(key, iv, plaintext):
	cipher = AES.new(key, AES.MODE_CBC, iv)
	ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
	return ciphertext

# D-H解密
def decrypt(key, iv, ciphertext):
	cipher = AES.new(key, AES.MODE_CBC, iv)
	plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
	return plaintext

# 数字签名
def sign(message, prv_key):
	rsa_key = RSA.importKey(prv_key)
	signer = PKCS1_v1_5.new(rsa_key)
	h = SHA256.new(message)
	return signer.sign(h)

# 验证签名
def verify(message, signature, pub_key):
	rsa_key = RSA.importKey(pub_key)
	verifier = PKCS1_v1_5.new(rsa_key)
	h = SHA256.new(message)
	return verifier.verify(h, signature)

# AES解密
def decrypt_AES(ciphertext, key, iv):
	cipher = AES.new(key, AES.MODE_CBC, iv)
	data = cipher.decrypt(ciphertext)
	unpadded_data = unpad(data, AES.block_size)
	return unpadded_data.decode()

# AES加密
def encrypt_AES(data, key, iv):
	cipher = AES.new(key, AES.MODE_CBC, iv)
	padded_data = pad(data.encode(), AES.block_size)
	ciphertext = cipher.encrypt(padded_data)
	return (ciphertext, iv)

def server_program():
	server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
	server_socket.bind(("127.0.0.1", 4008))  
	server_socket.listen(2)
	print '监听中......'
	conn, address = server_socket.accept()  
	print '客户端 %s:%s 已加入' % address	
	
	# S1: D-H密钥协商
	print 'D-H 密钥协商中......'
	data = conn.recv(4096)
	g = int(data[0])
	p = int(data[1:])
	if p != '':
		server_B, server_b = DHKeyExchange(p, g)
		conn.sendall(str(server_B))
	client_A = int(conn.recv(4096))
	key = DHComputeKey(client_A, server_b, p)
	print 'D-H 密钥协商成功。等待接收RSA公钥......'

	# S2: 接收Client公钥
	public_key = conn.recv(8192)
	print '收到RSA公钥。准备开始通信!'
	
	hl = hashlib.md5()
	# S3: 接收Client发来的密文和签名
	signature = conn.recv(4096)
	if signature != '':
		conn.sendall('ok')
	enc_msg = conn.recv(4096)
	
	# S4: 验证签名
	hl.update(enc_msg)
	if verify(hl.hexdigest(), signature, public_key):
		print '签名有效。继续......'
	else:
		print '签名无效。连接中断......'
		exit(-1)

	# S4: 解密
	iv = enc_msg[0:16]
	dec_msg = decrypt_AES(enc_msg[16:], key, iv).encode()
	print "收到秘密消息: %s" % dec_msg

if __name__ == '__main__':
	server_program()
