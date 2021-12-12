#Importing necessary modules
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from binascii import hexlify

private_key = RSA.generate(1024)
public_key = private_key.public_key()

private_pem = private_key.exportKey().decode()
public_pem = public_key.exportKey().decode()

# with open('ssl/.server_public.pem', 'w') as pub:
#     pub.write(public_pem)
# with open('ssl/.server_private.pem', 'w') as prv:
#     prv.write(private_pem)