from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA
import Crypto
from Crypto.PublicKey import RSA
from Crypto import Random
import base64


def rsakeys():  
     length=1024  
     privatekey = RSA.generate(length, Random.new().read)  
     publickey = privatekey.publickey()  
     return privatekey, publickey

def encrypt(rsa_publickey,plain_text):
     cipher_text=rsa_publickey.encrypt(plain_text,32)[0]
     b64cipher=base64.b64encode(cipher_text)
     return b64cipher

def decrypt(rsa_privatekey,b64cipher):
     decoded_ciphertext = base64.b64decode(b64cipher)
     plaintext = rsa_privatekey.decrypt(decoded_ciphertext)
     return plaintext

def sign(privatekey,data):
    signer = PKCS1_v1_5.new(privatekey)
    signature = signer.sign(data)
    signature64=base64.b64encode(signature)
    return signature64

privatekey,publickey=rsakeys()
text=b"Hello world!"

hashedDoc = SHA.new(text)

signatureB64 = sign(privatekey, hashedDoc)
signature = base64.b64decode(signatureB64) 
verifier = PKCS1_v1_5.new(publickey)
if verifier.verify(hashedDoc, signature):
  print ("The signature is authentic.")
else:
  print ("The signature is not authentic.")

hashedDoc_2 = SHA.new(b"Hello world")
if verifier.verify(hashedDoc_2, signature):
  print ("The signature is authentic.")
else:
  print ("The signature is not authentic.")
