def encode(data: str) -> str:
    return data.encode().hex()

def decode(data: str) -> str:
    return bytes.fromhex(data).decode()
