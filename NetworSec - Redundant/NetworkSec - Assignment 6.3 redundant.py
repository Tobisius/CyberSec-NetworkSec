import hashlib
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

def sign_combined_hash(private_key, combined_hash):
    message = combined_hash_bytes = bytes.fromhex(combined_hash)
    
    signature = private_key.sign(
        message,
        padding=padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        algorithm=hashes.SHA256()
    )
    
    return signature, combined_hash_bytes

def basic_verification(public_key, signature, combined_hash_bytes):
    try:
        public_key.verify(
            signature,
            combined_hash_bytes,
            padding=padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            algorithm=hashes.SHA256()
        )
        return True
    except InvalidSignature:
        print(f"Verification has failed")
        return False