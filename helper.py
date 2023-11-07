def author():
    print( """
    _      _    _    _____                      _ _         
    | |    | |  | |  / ____|                    (_) |        
    | |    | |__| | | (___   ___  ___ _   _ _ __ _| |_ _   _ 
    | |    |  __  |  \___ \ / _ \/ __| | | | '__| | __| | | |
    | |____| |  | |  ____) |  __/ (__| |_| | |  | | |_| |_| |
    |______|_|  |_| |_____/ \___|\___|\__,_|_|  |_|\__|\__, |
                                                        __/ |
                                                        |___/ 
    """ )

    
def display_help():
    print("""
Utility for encoding, decoding, hashing, and encrypting data.

Commands:
  base64    Base64 encode or decode. Use --encode or --decode flags.
  base16    Base16 encode or decode. Use --encode or --decode flags.
  base32    Base32 encode or decode. Use --encode or --decode flags.
  url       URL encode or decode. Use --encode or --decode flags.
  
  sha256    Generate SHA-256 hash.
  sha384    Generate SHA-384 hash.
  sha512    Generate SHA-512 hash.
  sha3_256  Generate SHA3-256 hash.
  sha3_512  Generate SHA3-512 hash.

  bf        Brute force a hashed password using a wordlist.
            Example: bf --password "hashed_password.txt" --wordlist "wordlist.txt" --format "sha256"

  rsa       RSA encryption and decryption.
            Encryption: rsa encrypt "Your Message Here"
            Decryption: rsa decrypt "Encrypted_Message" --privkey private_key.pem
            
  aes       AES encryption and decryption.
            Encryption: aes encrypt "Your Message Here"
            Decryption: aes decrypt "Encrypted_Message" --key aes_key
            
  caesar    Caesar Cipher decryption.
            Decryption: caesar --decode --shift 3 "Gdwd, phvvdjh!"

Type 'help' for this help message.
Type 'exit' to quit the application.
    """)

