import os
import hashlib
import mysql.connector
from cryptography.fernet import Fernet

# -----------------------------
# FILES
# -----------------------------
MASTER_FILE = "master.key"
KEY_FILE = "vault.key"

# -----------------------------
# MYSQL CONNECTION
# -----------------------------
def connect_db():
    return mysql.connector.connect(
        host="localhost",
        user="root",        # change if needed
        password="root",    # change if needed
        database="password_manager"
    )

# -----------------------------
# HASH MASTER PASSWORD
# -----------------------------
def hash_master_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# -----------------------------
# AUTHENTICATION
# -----------------------------
def authenticate_user():
    if not os.path.exists(MASTER_FILE):
        pwd = input("Create master password: ")
        with open(MASTER_FILE, "w") as f:
            f.write(hash_master_password(pwd))
        print("Master password created.\n")
    else:
        pwd = input("Enter master password: ")
        with open(MASTER_FILE, "r") as f:
            stored = f.read()
        if hash_master_password(pwd) != stored:
            print("Access denied.")
            exit()
        print("Access granted.\n")

# -----------------------------
# LOAD ENCRYPTION KEY
# -----------------------------
def load_vault():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
    else:
        with open(KEY_FILE, "rb") as f:
            key = f.read()
    return Fernet(key)

# -----------------------------
# ADD PASSWORD
# -----------------------------
def add_password(db, vault):
    site = input("Website/App: ")
    user = input("Username/Email: ")
    pwd = input("Password: ")

    cursor = db.cursor()
    sql = "INSERT INTO passwords (website, username, password) VALUES (%s, %s, %s)"
    values = (
        vault.encrypt(site.encode()).decode(),
        vault.encrypt(user.encode()).decode(),
        vault.encrypt(pwd.encode()).decode()
    )
    cursor.execute(sql, values)
    db.commit()
    print("Password stored successfully.\n")

# -----------------------------
# VIEW PASSWORDS
# -----------------------------
def view_passwords(db, vault):
    cursor = db.cursor()
    cursor.execute("SELECT * FROM passwords")
    rows = cursor.fetchall()

    if not rows:
        print("No passwords stored.\n")
        return

    print("\nSaved Passwords")
    print("----------------")
    for row in rows:
        print(f"[{row[0]}] Website : {vault.decrypt(row[1].encode()).decode()}")
        print(f"     Username: {vault.decrypt(row[2].encode()).decode()}")
        print(f"     Password: {vault.decrypt(row[3].encode()).decode()}\n")

# -----------------------------
# UPDATE PASSWORD
# -----------------------------
def update_password(db, vault):
    view_passwords(db, vault)
    pid = input("Enter ID to update: ")

    site = input("New Website/App: ")
    user = input("New Username: ")
    pwd = input("New Password: ")

    cursor = db.cursor()
    sql = """
        UPDATE passwords
        SET website=%s, username=%s, password=%s
        WHERE id=%s
    """
    values = (
        vault.encrypt(site.encode()).decode(),
        vault.encrypt(user.encode()).decode(),
        vault.encrypt(pwd.encode()).decode(),
        pid
    )
    cursor.execute(sql, values)
    db.commit()
    print("Password updated.\n")

# -----------------------------
# DELETE PASSWORD
# -----------------------------
def delete_password(db):
    pid = input("Enter ID to delete: ")
    cursor = db.cursor()
    cursor.execute("DELETE FROM passwords WHERE id=%s", (pid,))
    db.commit()
    print("Password deleted.\n")

# -----------------------------
# MAIN PROGRAM
# -----------------------------
def main():
    authenticate_user()
    vault = load_vault()
    db = connect_db()

    while True:
        print("Password Manager")
        print("1. Add Password")
        print("2. View Passwords")
        print("3. Update Password")
        print("4. Delete Password")
        print("5. Exit")

        choice = input("Choose option: ")

        if choice == "1":
            add_password(db, vault)
        elif choice == "2":
            view_passwords(db, vault)
        elif choice == "3":
            update_password(db, vault)
        elif choice == "4":
            delete_password(db)
        elif choice == "5":
            db.close()
            print("Program terminated.")
            break
        else:
            print("Invalid choice.\n")

if __name__ == "__main__":
    main()
