from tinyec import registry
from Crypto.Cipher import AES
import hashlib, secrets, binascii

def encrypt_AES_GCM(msg, secretKey):
    aesCipher = AES.new(secretKey, AES.MODE_GCM)
    # Performs AES encryption on the message using the secret key.
    ciphertext, authTag = aesCipher.encrypt_and_digest(msg)
    return (ciphertext, aesCipher.nonce, authTag)

def decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey):
    aesCipher = AES.new(secretKey, AES.MODE_GCM, nonce)
    # Performs AES decryption on the message using the secret key.
    plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)
    return plaintext

def ecc_point_to_256_bit_key(point):
    sha = hashlib.sha256(int.to_bytes(point.x, 32, 'big'))
    sha.update(int.to_bytes(point.y, 32, 'big'))
    return sha.digest()

curve = registry.get_curve('secp256r1')

def encrypt_ECC(msg, pubKey):
    # This is effectively Alice's private key, alpha.
    ciphertextPrivKey = secrets.randbelow(curve.field.n)
    # Create a point on the curve by multiplying alpha and point B. This is essentially alpha*beta*G.
    # This means that only Alice and Bob know alpha*beta and no listeners know this value. This makes
    # calculating the following point extremely difficult without alpha and beta. Typically the x value
    # of this point is used as the secret key.
    sharedECCKey = ciphertextPrivKey * pubKey
    # Format to 256-bit key
    secretKey = ecc_point_to_256_bit_key(sharedECCKey)
    # Encrypts the message to cipher text using the secret key
    ciphertext, nonce, authTag = encrypt_AES_GCM(msg, secretKey)
    # This following value is Alice's public key, alpha*G, which she will give back to Bob so that he can calc
    # the point P by doing (alpha*G)*beta.
    ciphertextPubKey = ciphertextPrivKey * curve.g
    return (ciphertext, nonce, authTag, ciphertextPubKey)

def decrypt_ECC(encryptedMsg, privKey):
    # Separate the values in the encryptedMsg object
    (ciphertext, nonce, authTag, ciphertextPubKey) = encryptedMsg
    # Bob calculates point P by using his private key. This is essentially beta*(alpha*G), however alpha*G
    # has already been calculated and a listener cannot calculate the private key, which is alpha*beta without
    # beta, which they don't have.
    sharedECCKey = privKey * ciphertextPubKey
    # Format to 256-bit key
    secretKey = ecc_point_to_256_bit_key(sharedECCKey)
    # Use the secret key to decrypt the ciphertext.
    plaintext = decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey)
    return plaintext

# Stores the message as bytes
msg = b"Testing if this works "

print("original msg:", msg)
# Create random private key. Think of this as Bob's private key, beta.
privKey = secrets.randbelow(curve.field.n)
# Create a point on the curve by doing the dot operation of beta and generator point G, we'll call it B.
# This will be exchanged publicly with Alice and someone can see this without being able to to calculate beta.
pubKey = privKey * curve.g

# encrypts message using encrypt_ECC function. Read through the function to see how.
encryptedMsg = encrypt_ECC(msg, pubKey)
# Format the cipher text into info an object.
encryptedMsgObj = {
    'ciphertext': binascii.hexlify(encryptedMsg[0]),
    'nonce': binascii.hexlify(encryptedMsg[1]),
    'authTag': binascii.hexlify(encryptedMsg[2]),
    'ciphertextPubKey': hex(encryptedMsg[3].x) + hex(encryptedMsg[3].y % 2)[2:]
}
print("encrypted msg:", encryptedMsgObj)

# Bob uses his private key to decrypt the message. Read through the function to see how.
decryptedMsg = decrypt_ECC(encryptedMsg, privKey)
print("decrypted msg:", decryptedMsg)