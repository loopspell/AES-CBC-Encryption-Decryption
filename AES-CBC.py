from Crypto.Cipher import AES
import binascii
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from Crypto.Random import get_random_bytes

def AES_Encrypt(data, key):
	cipher = AES.new(key, AES.MODE_CBC)
	pad_block = get_random_bytes(16)	# 16 byte random padding for AES encryption
	cipherText = cipher.encrypt(pad(data,AES.block_size))
	iv = cipher.iv
	return cipherText, iv

def AES_Decrypt(cipherText, key, iv):
	cipher = AES.new(key, AES.MODE_CBC, iv)
	plainText = unpad(cipher.decrypt(cipherText),AES.block_size)
	return plainText


operation = input("Enter the Operation you want to perform (Encryption/Decryption) - E/D:")

if operation == "E":
	plainText = input("Enter the Message you want to encrypt: ").encode("ASCII")  # user input and converting byte to string
	Secretkey = input("Enter the 16/24/32 byte of Secret Key: ").encode("ASCII")
	cipherText, iv = AES_Encrypt(plainText, Secretkey)
	print("CipherText: "+binascii.hexlify(cipherText).decode("ASCII")) # binary to hex conversation and converting byte to string
	print("IV: "+binascii.hexlify(iv).decode("ASCII"))

elif operation == "D":
	cipherText = input("Enter the CipherText which you want to decrypted: ").encode("ASCII") # convert string to byte
	cipherText = binascii.unhexlify(cipherText) # hex to binary coversation
	iv = input("Enter the IV used while encryption: ").encode("ASCII")
	iv = binascii.unhexlify(iv)
	Secretkey = input("Enter Secret Key: ").encode("ASCII")
	print("Plain Text: "+AES_Decrypt(cipherText, Secretkey, iv).decode("ASCII"))
else:
	exit(0)





