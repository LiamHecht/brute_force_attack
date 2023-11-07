import hashlib
import os


def brute_force(password, hash_format, wordlist_file=None,  direct=False):
    print(f"Starting brute force with:")

    if direct:
        hashed_password = password.strip()
        print(f"Direct Hashed Password: {hashed_password}")
    else:
        with open(password, 'r') as f:
            hashed_password = f.readline().strip()  # read only the first line and strip it
        print(f"Password File: {password}")

    print(f"Wordlist File: {wordlist_file}")
    print(f"Format: {hash_format}")

    # Read the wordlist
    if (wordlist == "" or wordlist == None):

        with open("wordlist/passwords-top-100.txt", 'r') as f:
            wordlist = f.readlines()
    else:
        with open(f"{wordlist}", 'r') as f:
            wordlist = f.readlines()


    hash_function = get_format(hash_format)
    for word in wordlist:
        word = word.strip()  # This will remove any newline or other whitespace from the end of the line
        print(word)
        hashed_word = hash_function(word.encode()).hexdigest()

        if hashed_word == hashed_password:
            print(f"Match found! Password: {word}")
            return f"We have successfully found your password. \nOriginal Password: {word} \nHashed Password: {hashed_word}"

    print("No matches found in the provided wordlist.")


def get_format(hash_format):
    if hash_format == "md5":
        return hashlib.md5
    elif hash_format == "sha1":
        return hashlib.sha1
    elif hash_format == "sha256":
        return hashlib.sha256
    elif hash_format == "sha512":
        return hashlib.sha512
    else:
        raise ValueError(f"Unsupported hash format: {hash_format}")

def identify_hash(hash_str):
    """Identify the hash algorithm used based on length."""
    hash_length = len(hash_str)

    # Dictionary mapping hash length to potential algorithms
    hash_id = {
        32: 'MD5',
        40: 'SHA1',
        56: 'SHA224',
        64: 'SHA256',
        96: 'SHA384',
        128: 'SHA512',
        # Add more if needed
    }

    return hash_id.get(hash_length, "Unknown")

