import os
import base64
import hashlib
from cryptography.fernet import Fernet

MASTER_FILE = "master.key"
VAULT_KEY_FILE = "vault.key"
PASSWORD_FILE = "passwords.txt"


# ----------------------------------------------------
# 1. HASHING MASTER PASSWORD
# ----------------------------------------------------
def hash_master_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


# ----------------------------------------------------
# 2. SETUP / VERIFY MASTER PASSWORD
# ----------------------------------------------------
def setup_master_password():
    if not os.path.exists(MASTER_FILE):
        print("No master password found. Let's create one.")
        pwd = input("Create master password: ")
        hashed = hash_master_password(pwd)

        with open(MASTER_FILE, "w") as f:
            f.write(hashed)

        print("Master password created successfully.\n")
    else:
        pwd = input("Enter master password: ")
        hashed = hash_master_password(pwd)

        with open(MASTER_FILE, "r") as f:
            stored = f.read().strip()

        if hashed != stored:
            print("Incorrect master password. Access denied.")
            exit()
        else:
            print("Access granted.\n")


# ----------------------------------------------------
# 3. ENCRYPTION / DECRYPTION KEY MANAGEMENT
# ----------------------------------------------------
def load_vault_key():
    if not os.path.exists(VAULT_KEY_FILE):
        key = Fernet.generate_key()
        with open(VAULT_KEY_FILE, "wb") as f:
            f.write(key)
    else:
        with open(VAULT_KEY_FILE, "rb") as f:
            key = f.read()

    return Fernet(key)


# ----------------------------------------------------
# 4. ADDING A PASSWORD ENTRY
# ----------------------------------------------------
def add_password(fernet):
    website = input("Website/Platform: ")
    username = input("Username/Email: ")
    password = input("Password: ")

    encrypted_site = fernet.encrypt(website.encode()).decode()
    encrypted_user = fernet.encrypt(username.encode()).decode()
    encrypted_pass = fernet.encrypt(password.encode()).decode()

    with open(PASSWORD_FILE, "a") as f:
        f.write(f"{encrypted_site}|{encrypted_user}|{encrypted_pass}\n")

    print("Password saved successfully.\n")


# ----------------------------------------------------
# 5. VIEW ALL PASSWORDS
# ----------------------------------------------------
def view_passwords(fernet):
    if not os.path.exists(PASSWORD_FILE):
        print("No passwords stored yet.\n")
        return

    with open(PASSWORD_FILE, "r") as f:
        lines = f.readlines()

    if not lines:
        print("No passwords found.\n")
        return

    print("\nSaved Passwords:")
    print("----------------")

    for i, line in enumerate(lines):
        try:
            site, user, pwd = line.strip().split("|")
            site = fernet.decrypt(site.encode()).decode()
            user = fernet.decrypt(user.encode()).decode()
            pwd = fernet.decrypt(pwd.encode()).decode()

            print(f"[{i}] Website: {site}")
            print(f"     Username: {user}")
            print(f"     Password: {pwd}\n")
        except:
            print(f"[{i}] (Error decrypting entry)\n")


# ----------------------------------------------------
# 6. DELETE PASSWORD ENTRY
# ----------------------------------------------------
def delete_password(fernet):
    if not os.path.exists(PASSWORD_FILE):
        print("No passwords to delete.\n")
        return

    with open(PASSWORD_FILE, "r") as f:
        lines = f.readlines()

    if not lines:
        print("There are no saved entries.\n")
        return

    print("Choose the entry number to delete:\n")
    view_passwords(fernet)

    try:
        idx = int(input("Enter index: "))
        if idx < 0 or idx >= len(lines):
            print("Invalid index.\n")
            return
    except ValueError:
        print("Invalid input.\n")
        return

    del lines[idx]

    with open(PASSWORD_FILE, "w") as f:
        f.writelines(lines)

    print("Entry deleted successfully.\n")


# ----------------------------------------------------
# 7. MAIN PROGRAM LOOP
# ----------------------------------------------------
def main():
    setup_master_password()
    f = load_vault_key()

    while True:
        print("Password Manager Menu:")
        print("1. Add Password")
        print("2. View Passwords")
        print("3. Delete Password")
        print("4. Exit")

        choice = input("Choose an option: ")

        if choice == "1":
            add_password(f)
        elif choice == "2":
            view_passwords(f)
        elif choice == "3":
            delete_password(f)
        elif choice == "4":
            print("Exiting...")
            break
        else:
            print("Invalid choice. Try again.\n")


if __name__ == "__main__":
    main()
