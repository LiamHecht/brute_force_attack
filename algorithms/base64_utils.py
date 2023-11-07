import base64

def encode(data: str) -> str:
    """Encode a string using Base64."""
    encoded = base64.b64encode(data.encode())
    return encoded.decode()

def decode(data: str) -> str:
    """Decode a Base64 encoded string."""
    decoded = base64.b64decode(data.encode())
    return decoded.decode()
