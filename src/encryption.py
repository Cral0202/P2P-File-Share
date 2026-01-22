from typing import Tuple

from cryptography.hazmat.primitives import hashes, serialization, padding as sym_pad
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_pad
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPrivateKey

#######
# AES #
#######

# Encrypt with AES
def aes_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()

# Decrypt with AES
def aes_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

# Add padding
def aes_add_padding(text: bytes) -> bytes:
    padder = sym_pad.PKCS7(128).padder()
    return padder.update(text) + padder.finalize()

# Remove padding
def aes_remove_padding(text: bytes) -> bytes:
    unpadder = sym_pad.PKCS7(128).unpadder()
    return unpadder.update(text) + unpadder.finalize()

#######
# RSA #
#######

# Generate RSA keys
def generate_rsa_keys() -> Tuple[rsa.RSAPublicKey, rsa.RSAPrivateKey]:
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    return private_key.public_key(), private_key

# Encrypt with RSA
def rsa_encrypt(plaintext: bytes, key: RSAPublicKey) -> bytes:
    return key.encrypt(
        plaintext,
        asym_pad.OAEP(
            mgf=asym_pad.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# Decrypt with RSA
def rsa_decrypt(ciphertext: bytes, key: RSAPrivateKey) -> bytes:
    return key.decrypt(
        ciphertext,
        asym_pad.OAEP(
            mgf=asym_pad.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# Sign with RSA
def rsa_sign(text: bytes, key: RSAPrivateKey) -> bytes:
    return key.sign(
        text,
        asym_pad.PSS(
            mgf=asym_pad.MGF1(hashes.SHA256()),
            salt_length=asym_pad.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

# Verifies text signature with RSA
def rsa_verify_signature(signature: bytes, text: bytes, key: RSAPublicKey) -> bool:
    try:
        key.verify(
            signature,
            text,
            asym_pad.PSS(
                mgf=asym_pad.MGF1(hashes.SHA256()),
                salt_length=asym_pad.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

# Serialize a public key object into bytes
def rsa_serialize_public_key(key: RSAPublicKey) -> bytes:
    return key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

# Deserialize the bytes into a public key object
def rsa_deserialize_public_key(key: bytes) -> RSAPublicKey:
    return serialization.load_pem_public_key(key)
