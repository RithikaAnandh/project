import random
import string
import os
from cryptography.fernet import Fernet

# Configuration Defaults
DEFAULT_LENGTH = 12
DEFAULT_INCLUDE_UPPERCASE = True
DEFAULT_INCLUDE_DIGITS = True
DEFAULT_INCLUDE_SPECIAL = True

# Utility to Validate Password
def validate_password(password, include_uppercase, include_digits, include_special):
    if include_uppercase and not any(char.isupper() for char in password):
        return False
    if include_digits and not any(char.isdigit() for char in password):
        return False
    if include_special and not any(char in string.punctuation for char in password):
        return False
    return True

# Password Generator Logic
def generate_password(length, include_uppercase, include_digits, include_special):
    characters = string.ascii_lowercase
    if include_uppercase:
        characters += string.ascii_uppercase
    if include_digits:
        characters += string.digits
    if include_special:
        characters += string.punctuation

    if len(characters) == 0:
        raise ValueError("No character sets selected!")

    password = ''.join(random.choice(characters) for _ in range(length))
    if not validate_password(password, include_uppercase, include_digits, include_special):
        return generate_password(length, include_uppercase, include_digits, include_special)

    return password

# Save and Load Passwords Securely
def load_key():
    if not os.path.exists("key.key"):
        with open("key.key", "wb") as key_file:
            key_file.write(Fernet.generate_key())
    with open("key.key", "rb") as key_file:
        return key_file.read()

def save_password(password, filename="passwords.txt"):
    key = load_key()
    cipher_suite = Fernet(key)
    encrypted_password = cipher_suite.encrypt(password.encode())

    with open(filename, "ab") as file:
        file.write(encrypted_password + b"\n")

def load_passwords(filename="passwords.txt"):
    key = load_key()
    cipher_suite = Fernet(key)

    if not os.path.exists(filename):
        return []

    with open(filename, "rb") as file:
        encrypted_passwords = file.readlines()

    return [cipher_suite.decrypt(pw.strip()).decode() for pw in encrypted_passwords]

# Securely Delete File
def secure_delete(filename):
    if os.path.exists(filename):
        with open(filename, "ba+", buffering=0) as file:
            length = file.tell()
        with open(filename, "br+", buffering=0) as file:
            file.write(b'\x00' * length)
        os.remove(filename)

# User Interface
def get_user_preferences():
    print("Welcome to the Strong Password Generator!")
    try:
        length = int(input(f"Enter the desired password length (default {DEFAULT_LENGTH}): ") or DEFAULT_LENGTH)
        include_uppercase = input("Include uppercase letters? (y/n, default y): ").lower() != 'n'
        include_digits = input("Include digits? (y/n, default y): ").lower() != 'n'
        include_special = input("Include special characters? (y/n, default y): ").lower() != 'n'
        return length, include_uppercase, include_digits, include_special
    except ValueError:
        print("Invalid input. Using default settings.")
        return DEFAULT_LENGTH, DEFAULT_INCLUDE_UPPERCASE, DEFAULT_INCLUDE_DIGITS, DEFAULT_INCLUDE_SPECIAL

if __name__ == "__main__":
    while True:
        print("\n--- Strong Password Generator ---")
        print("1. Generate a new password")
        print("2. View saved passwords")
        print("3. Securely delete saved passwords")
        print("4. Exit")
        choice = input("Choose an option: ")

        if choice == "1":
            length, include_uppercase, include_digits, include_special = get_user_preferences()
            password = generate_password(length, include_uppercase, include_digits, include_special)
            print(f"\nYour generated password is: {password}")
            save_option = input("Do you want to save this password? (y/n): ").lower()
            if save_option == 'y':
                save_password(password)
                print("Password saved securely!")
        elif choice == "2":
            print("\nSaved Passwords:")
            for pw in load_passwords():
                print(f"- {pw}")
        elif choice == "3":
            confirm = input("Are you sure you want to delete all saved passwords? (y/n): ").lower()
            if confirm == 'y':
                secure_delete("passwords.txt")
                print("All saved passwords have been securely deleted.")
        elif choice == "4":
            print("Exiting. Stay secure!")
            break
        else:
            print("Invalid choice. Please try again.")
