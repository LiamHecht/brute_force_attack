import hashlib

def sha256(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()

def sha384(data: str) -> str:
    return hashlib.sha384(data.encode()).hexdigest()

def sha512(data: str) -> str:
    return hashlib.sha512(data.encode()).hexdigest()
