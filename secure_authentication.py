import json
import os
import hashlib
import secrets

FILE = "users.json"


# Load registered users
def load_users():
    if os.path.exists(FILE):
        with open(FILE, "r") as f:
            return json.load(f)
    return {}


# Save users
def save_users(users):
    with open(FILE, "w") as f:
        json.dump(users, f, indent=4)


# Convert password into a secure hash
def hash_password(password, salt):
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        salt.encode(),
        200000
    ).hex()


# Register a new user
def register():
    users = load_users()

    username = input("Create username: ").strip()

    if not username:
        print("Username cannot be empty!")
        return

    if username in users:
        print("Username already exists!")
        return

    password = input("Create password: ")

    if len(password) < 8:
        print("Password must have at least 8 characters!")
        return

    salt = secrets.token_hex(16)
    password_hash = hash_password(password, salt)

    users[username] = {
        "salt": salt,
        "password_hash": password_hash
    }

    save_users(users)
    print("Registration successful!")


# Login an existing user
def login():
    users = load_users()

    username = input("Enter username: ").strip()
    password = input("Enter password: ")

    if username not in users:
        print("Invalid username or password!")
        return

    salt = users[username]["salt"]
    saved_hash = users[username]["password_hash"]

    entered_hash = hash_password(password, salt)

    if secrets.compare_digest(entered_hash, saved_hash):
        print("Login successful!")
        print("Welcome", username)
    else:
        print("Invalid username or password!")


# Main program
def main():
    while True:
        print("\n===== SECURE AUTHENTICATION SYSTEM =====")
        print("1. Register")
        print("2. Login")
        print("3. Exit")

        choice = input("Enter your choice: ")

        if choice == "1":
            register()

        elif choice == "2":
            login()

        elif choice == "3":
            print("Thank you for using the system!")
            break

        else:
            print("Invalid choice! Try again.")


main()
