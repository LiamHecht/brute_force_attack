def caesar_decrypt(ciphertext, shift):
    plaintext = ""
    for char in ciphertext:
        if char.isalpha():
            # Determine whether it's an uppercase or lowercase letter
            is_upper = char.isupper()
            char = char.lower()
            # Decrypt the character
            decrypted_char = chr(((ord(char) - ord('a') - shift) % 26) + ord('a'))
            if is_upper:
                decrypted_char = decrypted_char.upper()
            plaintext += decrypted_char
        else:
            plaintext += char
    return plaintext
def caesar_encrypt(plain_text, shift):
    encrypted_text = ""
    for char in plain_text:
        if char.isalpha():
            is_upper = char.isupper()
            shifted_char = chr(((ord(char) - ord('A' if is_upper else 'a') + shift) % 26) + ord('A' if is_upper else 'a'))
            encrypted_text += shifted_char
        else:
            encrypted_text += char
    return encrypted_text