from tkinter import Tk, Label, Button, Toplevel, Text, END, messagebox, Frame
from tkinter import ttk
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, hmac
import hashlib
import os

# Global variables
private_key = None
public_key = None

# Utility function for rounded frames
def create_rounded_frame(parent, bg_color):
    style = ttk.Style()
    style.configure("Rounded.TFrame", background=bg_color, borderwidth=2, relief="solid")
    frame = ttk.Frame(parent, style="Rounded.TFrame")
    return frame

# ----------------------------------------------
# Function to handle RSA operations
def rsa_window():
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

    rsa_window = Toplevel(root)
    rsa_window.title("RSA Digital Signature")
    rsa_window.geometry("700x500")
    rsa_window.configure(bg="#1e272e")

    frame = create_rounded_frame(rsa_window, "#2c3e50")
    frame.pack(pady=20, padx=20, fill="both", expand=True)

    Label(frame, text="Message:", font=("Arial", 12), bg="#2c3e50", fg="#ecf0f1").pack(pady=5)
    message_entry = Text(frame, height=5, width=60, bg="#34495e", fg="#ecf0f1", insertbackground="white")
    message_entry.pack(pady=5)

    Label(frame, text="Signature (Hex):", font=("Arial", 12), bg="#2c3e50", fg="#ecf0f1").pack(pady=5)
    signature_output = Text(frame, height=5, width=60, bg="#34495e", fg="#ecf0f1", insertbackground="white")
    signature_output.pack(pady=5)

    Button(frame, text="Generate Keys", command=generate_keys, bg="#3498db", fg="white", font=("Arial", 12)).pack(pady=10)
    Button(frame, text="Create Signature", command=create_signature, bg="#2ecc71", fg="white", font=("Arial", 12)).pack(pady=10)
    Button(frame, text="Verify Signature", command=verify_signature, bg="#e67e22", fg="white", font=("Arial", 12)).pack(pady=10)

# ----------------------------------------------
# Function to handle SHA operations
def sha_window():
    def generate_hash():
        message = message_entry.get("1.0", END).strip()
        if not message:
            messagebox.showerror("Error", "Message cannot be empty!")
            return
        hash_output.delete("1.0", END)
        hash_output.insert(END, hashlib.sha256(message.encode()).hexdigest())
        messagebox.showinfo("Hash Generated", "SHA-256 hash has been created!")

    sha_window = Toplevel(root)
    sha_window.title("SHA Hashing")
    sha_window.geometry("700x400")
    sha_window.configure(bg="#1e272e")

    frame = create_rounded_frame(sha_window, "#2c3e50")
    frame.pack(pady=20, padx=20, fill="both", expand=True)

    Label(frame, text="Message:", font=("Arial", 12), bg="#2c3e50", fg="#ecf0f1").pack(pady=5)
    message_entry = Text(frame, height=5, width=60, bg="#34495e", fg="#ecf0f1", insertbackground="white")
    message_entry.pack(pady=5)

    Label(frame, text="Hash Output (Hex):", font=("Arial", 12), bg="#2c3e50", fg="#ecf0f1").pack(pady=5)
    hash_output = Text(frame, height=5, width=60, bg="#34495e", fg="#ecf0f1", insertbackground="white")
    hash_output.pack(pady=5)

    Button(frame, text="Generate Hash", command=generate_hash, bg="#2ecc71", fg="white", font=("Arial", 12)).pack(pady=10)

# ----------------------------------------------
# Function to handle MAC operations
def mac_window():
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

    mac_window = Toplevel(root)
    mac_window.title("Message Authentication Code (MAC)")
    mac_window.geometry("700x400")
    mac_window.configure(bg="#1e272e")

    frame = create_rounded_frame(mac_window, "#2c3e50")
    frame.pack(pady=20, padx=20, fill="both", expand=True)

    Label(frame, text="Message:", font=("Arial", 12), bg="#2c3e50", fg="#ecf0f1").pack(pady=5)
    message_entry = Text(frame, height=5, width=60, bg="#34495e", fg="#ecf0f1", insertbackground="white")
    message_entry.pack(pady=5)

    Label(frame, text="MAC Output (Hex):", font=("Arial", 12), bg="#2c3e50", fg="#ecf0f1").pack(pady=5)
    mac_output = Text(frame, height=5, width=60, bg="#34495e", fg="#ecf0f1", insertbackground="white")
    mac_output.pack(pady=5)

    Button(frame, text="Generate MAC", command=generate_mac, bg="#2ecc71", fg="white", font=("Arial", 12)).pack(pady=10)

# ----------------------------------------------
# Main Window
root = Tk()
root.title("Cryptographic Operations")
root.geometry("500x400")
root.configure(bg="#1e272e")

frame = create_rounded_frame(root, "#2c3e50")
frame.pack(pady=50, padx=50, fill="both", expand=True)

Label(frame, text="Welcome to Cryptographic Operations", font=("Arial", 16, "bold"), bg="#2c3e50", fg="#ecf0f1").pack(pady=20)

Button(frame, text="RSA Digital Signature", command=rsa_window, bg="#3498db", fg="white", font=("Arial", 12)).pack(pady=10)
Button(frame, text="SHA Hashing", command=sha_window, bg="#2ecc71", fg="white", font=("Arial", 12)).pack(pady=10)
Button(frame, text="Message Authentication Code (MAC)", command=mac_window, bg="#e67e22", fg="white", font=("Arial", 12)).pack(pady=10)

# Run the application
root.mainloop()
