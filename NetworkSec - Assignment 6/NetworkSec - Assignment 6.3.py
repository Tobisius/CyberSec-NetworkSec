import hashlib
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes


PI = "Pay 100 DKK to MerchantX"
OI = "Order #2456: 2 items total 100 DKK"

def digest_message():
    PI_hash = hashlib.sha256(PI.encode()).hexdigest()
    OI_hash = hashlib.sha256(OI.encode()).hexdigest()
    combined_hash = hashlib.sha256((PI_hash + OI_hash).encode()).hexdigest()
    return PI_hash, OI_hash, combined_hash

def generate_rsa_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    
    return private_key, public_key

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
    except Exception as e:
        print(f"Verification failed: {e}")
        return False

if __name__ == "__main__":
    PI_hash, OI_hash, combined_hash = digest_message()
    print(f"Payment Instruction Hash: {PI_hash}")
    print(f"Order Information Hash: {OI_hash}")
    print(f"Combined Hash: {combined_hash}")
    private_key, public_key = generate_rsa_keypair()
    print(f"Private Key: {private_key}")
    print(f"Public Key: {public_key}")
    signature, combined_hash_bytes = sign_combined_hash(private_key, combined_hash)
    print(f"Signature: {signature}")
    print(f"Signature (Base64): {base64.b64encode(signature).decode('utf-8')}")
    is_valid = basic_verification(public_key, signature, combined_hash_bytes)
    print(f"Is the signature valid? {is_valid}")