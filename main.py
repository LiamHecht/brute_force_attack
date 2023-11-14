import argparse
from helper import author, display_help
from algorithms import base64_utils, base16_utils, base32_utils, url_utils, sha2_utils, sha3_utils,brute_force, rsa_utils, aes_utils
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend
import shlex

def execute(args):
    if args.algorithm == "base64":
        if args.encode:
            print(base64_utils.encode(args.data))
        elif args.decode:
            print(base64_utils.decode(args.data))
        else:
            print("You must specify either --encode or --decode.")

    elif args.algorithm == "base16":
        if args.encode:
            print(base16_utils.encode(args.data))
        elif args.decode:
            print(base16_utils.decode(args.data))
        else:
            print("You must specify either --encode or --decode.")

    elif args.algorithm == "base32":
        if args.encode:
            print(base32_utils.encode(args.data))
        elif args.decode:
            print(base32_utils.decode(args.data))
        else:
            print("You must specify either --encode or --decode.")

    elif args.algorithm == "url":
        if args.encode:
            print(url_utils.encode(args.data))
        elif args.decode:
            print(url_utils.decode(args.data))
        else:
            print("You must specify either --encode or --decode.")
    elif args.algorithm == "sha256":
        print(sha2_utils.sha256(args.data))

    elif args.algorithm == "sha384":
        print(sha2_utils.sha384(args.data))

    elif args.algorithm == "sha512":
        print(sha2_utils.sha512(args.data))

    elif args.algorithm == "sha3_256":
        print(sha3_utils.sha3_256(args.data))

    elif args.algorithm == "sha3_512":
        print(sha3_utils.sha3_512(args.data))
    elif args.algorithm == "bf":
        print(brute_force.brute_force(args.password, args.wordlist, args.format, args.direct))

    elif args.algorithm == "rsa":
        if args.action == "encrypt":
            # Generate private and public key
            private_key, public_key = rsa_utils.generate_keys()
            
            # Encrypt the data
            ciphertext = rsa_utils.encrypt(public_key, args.data)
            print(f"Ciphertext: {ciphertext}")
            
            # Save or display the private key for the user
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')
            print(f"Private Key: \n{private_pem}")
            
        elif args.action == "decrypt":
            # Load provided private key
            with open(args.privkey, "rb") as key_file:
                private_key = serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())
                
            # Decrypt the data
            plaintext = rsa_utils.decrypt(private_key, args.data)
            print(f"Plaintext: {plaintext}")
        else:
            print("You must specify either encrypt or decrypt action.")
    elif args.algorithm == "aes":
        if args.action == "encrypt":
            aes_key = aes_utils.generate_aes_key()
            ciphertext = aes_utils.aes_encrypt(aes_key, args.data)
            
            print(f"Ciphertext: {ciphertext.hex()}")
            print(f"AES Key: {aes_key.hex()}")
        elif args.action == "decrypt":
            key = bytes.fromhex(args.key)
            plaintext = aes_utils.aes_decrypt(key, bytes.fromhex(args.data))
            print(f"Plaintext: {plaintext}")
        else:
            print("You must specify either encrypt or decrypt action.")


    else:
        print(f"Unsupported algorithm: {args.algorithm}")


def main():
    parser = argparse.ArgumentParser(description="Utility for encoding and decoding data.", add_help=False)

    subparsers = parser.add_subparsers(dest="algorithm")
    
    #For Base64
    base64_parser = subparsers.add_parser("base64", help="Base64 encode or decode")
    base64_parser.add_argument("--encode", action="store_true", help="Encode data using Base64")
    base64_parser.add_argument("--decode", action="store_true", help="Decode data using Base64")
    base64_parser.add_argument("data", type=str, help="Data to be encoded or decoded")
    #For Base16
    base16_parser = subparsers.add_parser("base16", help="Base16 encode or decode")
    base16_parser.add_argument("--encode", action="store_true", help="Encode data using Base16")
    base16_parser.add_argument("--decode", action="store_true", help="Decode data using Base16")
    base16_parser.add_argument("data", type=str, help="Data to be encoded or decoded")
    #For Base32
    base32_parser = subparsers.add_parser("base32", help="Base32 encode or decode")
    base32_parser.add_argument("--encode", action="store_true", help="Encode data using Base32")
    base32_parser.add_argument("--decode", action="store_true", help="Decode data using Base32")
    base32_parser.add_argument("data", type=str, help="Data to be encoded or decoded")
    #For URl
    url_parser = subparsers.add_parser("url", help="URL encode or decode")
    url_parser.add_argument("--encode", action="store_true", help="Encode data for URLs")
    url_parser.add_argument("--decode", action="store_true", help="Decode data from URL format")
    url_parser.add_argument("data", type=str, help="Data to be encoded or decoded")

    # For SHA-2
    sha256_parser = subparsers.add_parser("sha256", help="SHA-256 hash")
    sha256_parser.add_argument("data", type=str, help="Data to be hashed")

    sha384_parser = subparsers.add_parser("sha384", help="SHA-384 hash")
    sha384_parser.add_argument("data", type=str, help="Data to be hashed")

    sha512_parser = subparsers.add_parser("sha512", help="SHA-512 hash")
    sha512_parser.add_argument("data", type=str, help="Data to be hashed")

    # For SHA-3
    sha3_256_parser = subparsers.add_parser("sha3_256", help="SHA3-256 hash")
    sha3_256_parser.add_argument("data", type=str, help="Data to be hashed")

    sha3_512_parser = subparsers.add_parser("sha3_512", help="SHA3-512 hash")
    sha3_512_parser.add_argument("data", type=str, help="Data to be hashed")

    #For Brute Force
    bf_parser = subparsers.add_parser("bf", help="Brute force a hashed password using a wordlist.")
    bf_parser.add_argument("--password", type=str, required=True, help="Direct hash or path to the password file.")
    bf_parser.add_argument("--wordlist", type=str, required=False, help="Path to the wordlist file.")
    bf_parser.add_argument("--format", type=str, choices=["md5", "sha1", "sha256", "sha512"], required=True, help="Hashing algorithm to use.")
    bf_parser.add_argument("--direct", action="store_true", help="Indicate if the password is a direct hash instead of a file path.")

    rsa_parser = subparsers.add_parser("rsa", help="RSA encrypt or decrypt")
    rsa_parser.add_argument("action", type=str, choices=["encrypt", "decrypt"], help="Action to perform: encrypt or decrypt.")
    rsa_parser.add_argument("data", type=str, help="Data to be encrypted or decrypted.")
    rsa_parser.add_argument("--privkey", type=str, help="Path to the RSA private key file for decryption.")

    aes_parser = subparsers.add_parser("aes", help="AES encrypt or decrypt")
    aes_parser.add_argument("action", type=str, choices=["encrypt", "decrypt"], help="Action to perform: encrypt or decrypt.")
    aes_parser.add_argument("data", type=str, help="Data to be encrypted or decrypted.")
    aes_parser.add_argument("--key", type=str, help="Hex encoded AES key for decryption.")


    print("Type 'exit' to quit.")


    while True:
        user_input = input("> ").strip()

        if user_input.lower() == 'help':
            display_help()
        if user_input.lower() == 'exit':
            break

        try:
            args = parser.parse_args(shlex.split(user_input))
            execute(args)
        except Exception as e:
            print(f"Error: {e}")
            parser.print_help()

if __name__ == "__main__":
    author()    
    display_help()    
    main()
