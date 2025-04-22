import streamlit as st  # type: ignore
from cryptography.fernet import Fernet  # type: ignore
import hashlib
import json
import os
import time
import base64
import secrets
from datetime import datetime, timedelta

# --------------------- Constants & Initialization --------------------- #
data_file = "data.json"
lockout_file = "lockout.json"
stored_data = {}
users = {"admin": "admin"}  # username: password

# Load data from file if exists
def load_data():
    global stored_data
    if os.path.exists(data_file):
        with open(data_file, "r") as file:
            stored_data = json.load(file)

# Save data to file
def save_data():
    with open(data_file, "w") as file:
        json.dump(stored_data, file)

# Load lockout info
def load_lockout():
    if os.path.exists(lockout_file):
        with open(lockout_file, "r") as file:
            return json.load(file)
    return {}

# Save lockout info
def save_lockout(info):
    with open(lockout_file, "w") as file:
        json.dump(info, file)

# --------------------- Hashing & Encryption --------------------- #
def hash_passkey_pbkdf2(passkey, salt=None):
    if not salt:
        salt = secrets.token_bytes(16)
    key = hashlib.pbkdf2_hmac("sha256", passkey.encode(), salt, 100000)
    return base64.b64encode(salt + key).decode()

def verify_passkey_pbkdf2(stored_hash, passkey):
    data = base64.b64decode(stored_hash.encode())
    salt = data[:16]
    new_hash = hashlib.pbkdf2_hmac("sha256", passkey.encode(), salt, 100000)
    return new_hash == data[16:]

def generate_fernet_key(passkey):
    key = hashlib.sha256(passkey.encode()).digest()
    return base64.urlsafe_b64encode(key)

def encrypt_text(text, passkey):
    f = Fernet(generate_fernet_key(passkey))
    return f.encrypt(text.encode()).decode()

def decrypt_text(encrypted_text, passkey):
    f = Fernet(generate_fernet_key(passkey))
    return f.decrypt(encrypted_text.encode()).decode()

# --------------------- UI Pages --------------------- #
def login_page():
    st.title("🔐 Login Required")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        if username in users and users[username] == password:
            st.session_state.is_logged_in = True
            st.session_state.failed_attempts = 0
            st.success("Login successful!")
        else:
            st.error("Invalid credentials")

def home_page():
    st.title("📁 Secure Data Storage")
    choice = st.selectbox("Choose an option", ["Insert Data", "Retrieve Data"])
    if choice == "Insert Data":
        insert_data_page()
    elif choice == "Retrieve Data":
        retrieve_data_page()

def insert_data_page():
    st.subheader("Store Your Secure Data")
    user_id = st.text_input("Enter unique ID")
    text = st.text_area("Enter data")
    passkey = st.text_input("Enter passkey", type="password")
    if st.button("Store"):
        if user_id in stored_data:
            st.warning("ID already exists!")
            return
        hashed_key = hash_passkey_pbkdf2(passkey)
        encrypted = encrypt_text(text, passkey)
        stored_data[user_id] = {"encrypted_text": encrypted, "passkey": hashed_key}
        save_data()
        st.success("Data stored securely!")

def retrieve_data_page():
    st.subheader("Retrieve Your Secure Data")
    user_id = st.text_input("Enter your ID")
    passkey = st.text_input("Enter your passkey", type="password")
    lockout_info = load_lockout()
    now = datetime.now()
    locked_until = lockout_info.get("locked_until")
    
    if locked_until and datetime.strptime(locked_until, "%Y-%m-%d %H:%M:%S") > now:
        st.error(f"Too many failed attempts. Try again after {locked_until}")
        return

    if st.button("Retrieve"):
        if user_id not in stored_data:
            st.error("ID not found")
            return

        stored = stored_data[user_id]
        if verify_passkey_pbkdf2(stored["passkey"], passkey):
            decrypted = decrypt_text(stored["encrypted_text"], passkey)
            st.success("Decryption successful!")
            st.write(f"Decrypted Data: {decrypted}")
            st.session_state.failed_attempts = 0
        else:
            st.session_state.failed_attempts += 1
            st.error("Incorrect passkey")
            if st.session_state.failed_attempts >= 3:
                lock_time = (now + timedelta(seconds=30)).strftime("%Y-%m-%d %H:%M:%S")
                save_lockout({"locked_until": lock_time})
                st.error("Too many failed attempts. Locked for 30 seconds.")

# --------------------- App Logic --------------------- #
def main():
    st.set_page_config(page_title="Secure Storage App")
    load_data()
    if "failed_attempts" not in st.session_state:
        st.session_state.failed_attempts = 0
    if "is_logged_in" not in st.session_state:
        st.session_state.is_logged_in = True

    if not st.session_state.is_logged_in:
        login_page()
    else:
        home_page()

if __name__ == "__main__":
    main()
