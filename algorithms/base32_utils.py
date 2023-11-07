import base64

def encode(data: str) -> str:
    return base64.b32encode(data.encode()).decode()

def decode(data: str) -> str:
    return base64.b32decode(data.encode()).decode()
