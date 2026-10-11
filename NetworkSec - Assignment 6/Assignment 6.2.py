from ecdsa import SigningKey
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, padding
from cryptography.hazmat.primitives import hashes
import base64
import time
import tracemalloc

def rsa_sign():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    message = b"Educative authorizes this shot"
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode('utf-8')

def dsa_sign():
    private_key = dsa.generate_private_key(
        key_size=2048,
    )
    message = b"Educative authorizes this shot"
    signature = private_key.sign(
        message,
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode('utf-8')


def ecdsa_sign():   
    private_key = SigningKey.generate() # uses NIST192p
    signature = private_key.sign(b"Educative authorizes this shot")
    return base64.b64encode(signature).decode('utf-8')

if __name__ == "__main__":
    timersa = []
    timerdsa = []
    timerecdsa = []
    for i in range(1):
        print("Iteration:", i + 1)
        time_start = time.time()
        rsa_signature = rsa_sign()
        time_end = time.time()
        timersa.append(time_end - time_start)
        print("RSA signing time:", time_end - time_start, "seconds")
        time_start = time.time()
        dsa_signature = dsa_sign()
        time_end = time.time()
        timerdsa.append(time_end - time_start)
        print("DSA signing time:", time_end - time_start, "seconds")
        time_start = time.time()
        ecdsa_signature = ecdsa_sign()
        time_end = time.time()
        timerecdsa.append(time_end - time_start)
        print("ECDSA signing time:", time_end - time_start, "seconds")
        print("RSA Signature:", rsa_signature, "\n")
        print("DSA Signature:", dsa_signature, "\n")
        print("ECDSA Signature:", ecdsa_signature)
        
    print("Average RSA signing time:", sum(timersa) / len(timersa), "seconds")
    print("Average DSA signing time:", sum(timerdsa) / len(timerdsa), "seconds")
    print("Average ECDSA signing time:", sum(timerecdsa) / len(timerecdsa), "seconds")

    # Print memory usage
    tracemalloc.start()
    tracemalloc.take_snapshot()
    
    rsa_signature = rsa_sign()
    
    current, peak = tracemalloc.get_traced_memory()
    print("RSA")
    print(f"Current memory usage: {current / 1024 / 1024:.20f} MB")
    print(f"Peak memory usage: {peak / 1024 / 1024:.20f} MB")

    tracemalloc.stop()
    tracemalloc.start()
    tracemalloc.take_snapshot()
    
    dsa_signature = dsa_sign()
    
    current, peak = tracemalloc.get_traced_memory()
    print("DSA")
    print(f"Current memory usage: {current / 1024 / 1024:.20f} MB")
    print(f"Peak memory usage: {peak / 1024 / 1024:.20f} MB")

    tracemalloc.stop()
    
    tracemalloc.start()
    tracemalloc.take_snapshot()

    ecdsa_signature = ecdsa_sign()
    
    current, peak = tracemalloc.get_traced_memory()
    print("ECDSA")
    print(f"Current memory usage: {current / 1024 / 1024:.20f} MB")
    print(f"Peak memory usage: {peak / 1024 / 1024:.20f} MB")

    tracemalloc.stop()