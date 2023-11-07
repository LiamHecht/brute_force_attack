import hashlib

def sha3_256(data: str) -> str:
    return hashlib.sha3_256(data.encode()).hexdigest()

def sha3_512(data: str) -> str:
    return hashlib.sha3_512(data.encode()).hexdigest()
