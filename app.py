import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# Generate a key (for demo only; should be securely stored in production)
KEY = Fernet.generate_key()
cipher = Fernet(KEY)

# In-memory storage
stored_data = {}  # Format: {"encrypted_text": {"encrypted_text": ..., "passkey": ...}}
failed_attempts = 0
MAX_ATTEMPTS = 3

# Hashing function
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Encryption function
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

# Decryption function
def decrypt_data(encrypted_text, passkey):
    global failed_attempts
    hashed_passkey = hash_passkey(passkey)

    entry = stored_data.get(encrypted_text)
    if entry and entry["passkey"] == hashed_passkey:
        failed_attempts = 0
        return cipher.decrypt(encrypted_text.encode()).decode()
    else:
        failed_attempts += 1
        return None

# Streamlit UI
st.title("🔐 Secure Data Encryption System")
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

# Pages
if choice == "Home":
    st.subheader("🏠 Welcome")
    st.write("Store and retrieve encrypted data securely using your passkey.")

elif choice == "Store Data":
    st.subheader("📥 Store Data")
    user_data = st.text_area("Enter data to encrypt")
    passkey = st.text_input("Enter passkey", type="password")

    if st.button("Encrypt & Store"):
        if user_data and passkey:
            hashed = hash_passkey(passkey)
            encrypted = encrypt_data(user_data)
            stored_data[encrypted] = {"encrypted_text": encrypted, "passkey": hashed}
            st.success("✅ Data encrypted and stored successfully!")
            st.code(encrypted, language='text')
        else:
            st.error("⚠️ Please enter both data and passkey.")

elif choice == "Retrieve Data":
    st.subheader("🔓 Retrieve Data")
    encrypted_text = st.text_area("Paste encrypted data")
    passkey = st.text_input("Enter passkey", type="password")

    if st.button("Decrypt"):
        if encrypted_text and passkey:
            result = decrypt_data(encrypted_text, passkey)

            if result:
                st.success("✅ Decrypted Data:")
                st.code(result, language='text')
            else:
                remaining = MAX_ATTEMPTS - failed_attempts
                st.error(f"❌ Incorrect passkey! Attempts remaining: {remaining}")

                if failed_attempts >= MAX_ATTEMPTS:
                    st.warning("🔒 Too many failed attempts. Redirecting to login...")
                    st.experimental_rerun()
        else:
            st.error("⚠️ Please provide encrypted data and a passkey.")

elif choice == "Login":
    st.subheader("🔐 Login")
    master_password = st.text_input("Enter master password to reset attempts", type="password")

    if st.button("Login"):
        if master_password == "admin123":
            failed_attempts = 0
            st.success("✅ Reauthorized successfully!")
            st.experimental_rerun()
        else:
            st.error("❌ Incorrect master password.")
