import os
from hashlib import sha256
from getpass import getpass
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# Function to generate a salt for the password
def generate_salt():
    return os.urandom(16)

# Function to generate PBKDF2 key with blake2b hash
def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.BLAKE2b(64),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return kdf.derive(password)

# Encrypt some shit
def encrypt(file_path, password):
    # Use the salt function
    salt = generate_salt()

    # Use the key function with salt to hash password
    key = derive_key(password, salt)

    # Generate a nonce for file encryption
    nonce = os.urandom(12)

    # Init ChaCha20-Poly1305 cipher
    cipher = ChaCha20Poly1305(key)

    # Open the file
    with open(file_path, "rb") as file:
        file_data = file.read()

    # Save SHA256 hash of files to var
    file_data_hash = sha256(file_data).hexdigest()
    file_data_hash_bytes = file_data_hash.encode()

    # Print SHA256 from var
    print("Unencrypted file SHA256 (decrypted file should match):")
    print(file_data_hash)

    # Encrypt the data
    encrypted_data = cipher.encrypt(nonce, file_data, None)

    # Create output file path var
    output_file_path = file_path + ".enc"

    # Write the salt, nonce, and encrypted data to the output
    with open(output_file_path, "wb") as output_file:
        output_file.write(salt)
        output_file.write(nonce)
        output_file.write(encrypted_data)

    # Print success
    print("File encrypted successfully.")

# Decrypt some shit
def decrypt(file_path, password):
    # Check if it's an encrypted file
    if not file_path.endswith(".enc"):
        print("Not en encrypted file. Make sure it has the .enc extension.")
        return
    # Read the encrypted file
    with open(file_path, "rb") as file:
        # Read the salt
        salt = file.read(16)

        # Read the nonce
        nonce = file.read(12)

        # Read the encrypted data
        encrypted_data = file.read()

    # Use the key function to derive the key of encrypted file
    key = derive_key(password, salt)

    # Init the ChaCha20-Poly1305 cipher
    cipher = ChaCha20Poly1305(key)

    # Decrypt the data
    try:
        decrypted_data = cipher.decrypt(nonce, encrypted_data, None)
    except Exception as e:
        print("Decryption failed. Is the password correct?")
        return

    # Create output file path var
    output_file_path = file_path[:-4]  # Remove the ".enc" extension

    # Write the decrypted data to the output
    with open(output_file_path, "wb") as output_file:
        output_file.write(decrypted_data)

    # Print SHA256 of decrypted file
    print("Decrypted file SHA256 (should match original file):")
    print(sha256(decrypted_data).hexdigest())

    # Print success
    print("File decrypted successfully.")

def main():
    # Welcome message
    print("Welcome to PyCrypt v0.0.2. This is only a hobby project. It has not been audited. Don't trust it with important shit.")
    # Prompt for encrypt or decrypt
    action = input("Do you want to encrypt or decrypt a file? (e/d): ")

    # Prompt for the password
 #   password = input("Enter the password: ").encode()
    password = getpass().encode()

    # Prompt for the file name or path
    file_path = input("Enter the file path, or just file name if in current directory: ")

    if action.lower() == "e":
        encrypt(file_path, password)
    elif action.lower() == "d":
        decrypt(file_path, password)
    else:
        print("Invalid action. Please type either 'e' for encrypt or 'd' for decrypt.")

# Run main function
if __name__ == "__main__":
    main()
