import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature


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


    
    
def merchant_verification(public_key, signature, PI_hash, OI):
    OI_hash = hashlib.sha256(OI.encode()).hexdigest()
    combined_hash = hashlib.sha256((PI_hash + OI_hash).encode()).hexdigest()
    combined_hash_bytes = bytes.fromhex(combined_hash)
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
        
        print(f"Merchant verification has succeeded")
        return True
    except InvalidSignature:
        print(f"Merchant verification has failed")
        return False
    
def merchant_verification_tampered(public_key, signature, PI_hash):
    OI = "Order #2456: 3 items total 100 DKK"
    OI_hash = hashlib.sha256(OI.encode()).hexdigest()
    combined_hash = hashlib.sha256((PI_hash + OI_hash).encode()).hexdigest()
    combined_hash_bytes = bytes.fromhex(combined_hash)
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
        
        print(f"The tampered merchant verification has succeeded")
        return True
    except InvalidSignature:
        print(f"The tampered merchant verification has failed")
        return False
    
def payment_verification(public_key, signature, PI, OI_hash):
    PI_hash = hashlib.sha256(PI.encode()).hexdigest()
    combined_hash = hashlib.sha256((PI_hash + OI_hash).encode()).hexdigest()
    combined_hash_bytes = bytes.fromhex(combined_hash)
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
        print(f"Payment verification has succeeded")
        return True
    except InvalidSignature:
        print(f"Payment verification has failed")
        return False
    
    
def payment_verification_tampered(public_key, signature, OI_hash):
    PI = "Pay 200 DKK to MerchantX"
    PI_hash = hashlib.sha256(PI.encode()).hexdigest()
    combined_hash = hashlib.sha256((PI_hash + OI_hash).encode()).hexdigest()
    combined_hash_bytes = bytes.fromhex(combined_hash)
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
        print(f"The tampered payment verification has succeeded")
        return True
    except InvalidSignature:
        print(f"The tampered payment verification has failed")
        return False

if __name__ == "__main__":
    PI_hash, OI_hash, combined_hash = digest_message()
    private_key, public_key = generate_rsa_keypair()
    signature, combined_hash_bytes = sign_combined_hash(private_key, combined_hash)
    merchant_verification(public_key, signature, PI_hash, OI)
    payment_verification(public_key, signature, PI, OI_hash)
    merchant_verification_tampered(public_key, signature, PI_hash)
    payment_verification_tampered(public_key, signature, OI_hash)
