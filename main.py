# This is a sample Python script.
from hashlib import sha512;
from Crypto.PublicKey import RSA

message = b"Hi bitcoin@"
#print(message)

hashed = int.from_bytes(sha512(message).digest(), byteorder='big')
#print(sha512(message))
#print(hashed)

keyPair = RSA.generate(bits =1024)
message = b"Original Message"
hashedMessage = int.from_bytes(sha512(message).digest(), byteorder='big')

signature = pow(hashedMessage, keyPair.d, keyPair.n)
#print(hex(signature))
hashedFromSignature = pow(signature, keyPair.e, keyPair.n)
print(hashedMessage)
print(hashedFromSignature)

print(b"original message", hex(signature))

hashedMessage2 = int.from_bytes(sha512(b"original message").digest(), byteorder='big')
print(hashedMessage2)