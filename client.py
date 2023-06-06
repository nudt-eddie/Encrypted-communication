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
from Crypto import Random

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

def client_program():
	# 生成密钥对
	random_generator = Random.new().read
	key = RSA.generate(2048, random_generator)

	# 导出公钥和私钥
	private_key = key.exportKey()
	public_key = key.publickey().exportKey()

	client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
	client_socket.connect(('127.0.0.1', 4008))  

	# S1: D-H密钥协商
	print 'D-H 密钥协商中......'
	p = eval(raw_input('请输入素数: '))
	g = eval(raw_input('请输入原根: '))
	client_A, client_a = DHKeyExchange(p, g)
	client_socket.send(str(g) +str(p))
	status = client_socket.recv(4096)
	if status == '':
		print('D-H 密钥交换失败!')
		exit(-1)
	client_socket.send(str(client_A))
	server_B = int(status)
	key = DHComputeKey(server_B, client_a, p)
	print 'D-H 密钥协商成功。发送RSA公钥中......'
	
	# S2: 向Server发送公钥
	client_socket.send(public_key)

	hl = hashlib.md5()

	# S3: 向Server发送签名和密文
	message = raw_input('请输入秘密消息: ')
	iv = get_random_bytes(16)
	encrypted_message, iv = encrypt_AES(message, key, iv)

	msg = iv + encrypted_message
	hl.update(msg)
	signature = sign(hl.hexdigest(),private_key)

	client_socket.send(signature)
	status = client_socket.recv(4096)
	if status == 'ok':
		client_socket.send(msg)
		print '消息已发送'
	else:
		print '签名错误! '
		exit(-1)

	client_socket.close()
if __name__ == '__main__':
	client_program()
