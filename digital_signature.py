from tkinter import Tk, Label, Button, Toplevel, Text, END, messagebox
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives import serialization
import hashlib
import os

# Global variables
private_key = None
public_key = None
rsa_window_instance = None
sha_window_instance = None
mac_window_instance = None

# ----------------------------------------------
# Function to handle RSA operations
def rsa_window():
    global rsa_window_instance
    if rsa_window_instance is not None and rsa_window_instance.winfo_exists():
        rsa_window_instance.lift()
        return

    def generate_keys():
        global private_key, public_key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()
        messagebox.showinfo("Keys Generated", "RSA Key Pair has been generated!")

    def create_signature():
        if not private_key:
            messagebox.showerror("Error", "Generate RSA Keys first!")
            return
        message = message_entry.get("1.0", END).strip()
        if not message:
            messagebox.showerror("Error", "Message cannot be empty!")
            return
        message_hash = hashlib.sha256(message.encode()).digest()
        signature = private_key.sign(
            message_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        signature_output.delete("1.0", END)
        signature_output.insert(END, signature.hex())
        messagebox.showinfo("Signature Created", "Digital Signature has been created!")

    def verify_signature():
        if not public_key:
            messagebox.showerror("Error", "Generate RSA Keys first!")
            return
        message = message_entry.get("1.0", END).strip()
        signature = signature_output.get("1.0", END).strip()
        if not message or not signature:
            messagebox.showerror("Error", "Message and Signature cannot be empty!")
            return
        message_hash = hashlib.sha256(message.encode()).digest()
        try:
            signature_bytes = bytes.fromhex(signature)
            public_key.verify(
                signature_bytes,
                message_hash,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            messagebox.showinfo("Verification Successful", "Signature is valid!")
        except Exception as e:
            messagebox.showerror("Verification Failed", "Signature is invalid!")

    rsa_window_instance = Toplevel(root)
    rsa_window_instance.title("RSA Digital Signature")
    rsa_window_instance.geometry("600x500")

    Label(rsa_window_instance, text="Message:", font=("Arial", 12)).pack(pady=5)
    message_entry = Text(rsa_window_instance, height=5, width=60)
    message_entry.pack(pady=5)

    Label(rsa_window_instance, text="Signature (Hex):", font=("Arial", 12)).pack(pady=5)
    signature_output = Text(rsa_window_instance, height=5, width=60)
    signature_output.pack(pady=5)

    Button(rsa_window_instance, text="Generate Keys", command=generate_keys, bg="blue", fg="white", font=("Arial", 12)).pack(pady=10)
    Button(rsa_window_instance, text="Create Signature", command=create_signature, bg="green", fg="white", font=("Arial", 12)).pack(pady=10)
    Button(rsa_window_instance, text="Verify Signature", command=verify_signature, bg="orange", fg="white", font=("Arial", 12)).pack(pady=10)

# ----------------------------------------------
# Function to handle SHA operations
def sha_window():
    global sha_window_instance
    if sha_window_instance is not None and sha_window_instance.winfo_exists():
        sha_window_instance.lift()
        return

    def generate_hash():
        message = message_entry.get("1.0", END).strip()
        if not message:
            messagebox.showerror("Error", "Message cannot be empty!")
            return
        hash_output.delete("1.0", END)
        hash_output.insert(END, hashlib.sha256(message.encode()).hexdigest())
        messagebox.showinfo("Hash Generated", "SHA-256 hash has been created!")

    sha_window_instance = Toplevel(root)
    sha_window_instance.title("SHA Hashing")
    sha_window_instance.geometry("600x400")

    Label(sha_window_instance, text="Message:", font=("Arial", 12)).pack(pady=5)
    message_entry = Text(sha_window_instance, height=5, width=60)
    message_entry.pack(pady=5)

    Label(sha_window_instance, text="Hash Output (Hex):", font=("Arial", 12)).pack(pady=5)
    hash_output = Text(sha_window_instance, height=5, width=60)
    hash_output.pack(pady=5)

    Button(sha_window_instance, text="Generate Hash", command=generate_hash, bg="green", fg="white", font=("Arial", 12)).pack(pady=10)

# ----------------------------------------------
# Function to handle MAC operations
def mac_window():
    global mac_window_instance
    if mac_window_instance is not None and mac_window_instance.winfo_exists():
        mac_window_instance.lift()
        return

    def generate_mac():
        key = os.urandom(16)  # Random 16-byte key
        message = message_entry.get("1.0", END).strip()
        if not message:
            messagebox.showerror("Error", "Message cannot be empty!")
            return
        h = hmac.HMAC(key, hashes.SHA256())
        h.update(message.encode())
        mac_output.delete("1.0", END)
        mac_output.insert(END, h.finalize().hex())
        messagebox.showinfo("MAC Generated", "Message Authentication Code (MAC) has been created!")

    mac_window_instance = Toplevel(root)
    mac_window_instance.title("Message Authentication Code (MAC)")
    mac_window_instance.geometry("600x400")

    Label(mac_window_instance, text="Message:", font=("Arial", 12)).pack(pady=5)
    message_entry = Text(mac_window_instance, height=5, width=60)
    message_entry.pack(pady=5)

    Label(mac_window_instance, text="MAC Output (Hex):", font=("Arial", 12)).pack(pady=5)
    mac_output = Text(mac_window_instance, height=5, width=60)
    mac_output.pack(pady=5)

    Button(mac_window_instance, text="Generate MAC", command=generate_mac, bg="green", fg="white", font=("Arial", 12)).pack(pady=10)

# ----------------------------------------------
# Main Window
root = Tk()
root.title("Cryptographic Operations")
root.geometry("400x300")

Label(root, text="Choose an Operation", font=("Arial", 16)).pack(pady=20)

Button(root, text="RSA Digital Signature", command=rsa_window, bg="blue", fg="white", font=("Arial", 12), width=20).pack(pady=10)
Button(root, text="SHA Hashing", command=sha_window, bg="green", fg="white", font=("Arial", 12), width=20).pack(pady=10)
Button(root, text="MAC Generation", command=mac_window, bg="orange", fg="white", font=("Arial", 12), width=20).pack(pady=10)

root.mainloop()
