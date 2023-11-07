import urllib.parse

def encode(data: str) -> str:
    return urllib.parse.quote(data)

def decode(data: str) -> str:
    return urllib.parse.unquote(data)
