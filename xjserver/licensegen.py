#!/usr/bin/env python3
"""
License Generator with UI (RSA Digital Signature)
- Generates RSA public/private keys
- Signs MAC address as license
- Shows results in scrollable UI (copy & paste)
"""

import tkinter as tk
from tkinter import messagebox, scrolledtext
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import base64
import json 

private_key = None
public_key = None

def generate_keypair():
    global private_key, public_key

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    # Convert to PEM strings
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    txt_private.delete("1.0", tk.END)
    txt_private.insert(tk.END, private_pem)

    txt_public.delete("1.0", tk.END)
    txt_public.insert(tk.END, public_pem)

    messagebox.showinfo("Success", "RSA Keypair Generated!")

def sign_license():
    global private_key
    if not private_key:
        messagebox.showerror("Error", "Generate keys first!")
        return

    mac = entry_mac.get().strip()
    if not mac:
        messagebox.showerror("Error", "Enter a MAC address")
        return

    # The MAC address is the message to sign
    message_bytes = mac.encode()

    signature = private_key.sign(
        message_bytes,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    license_data = {
        "mac": mac,
        "signature": base64.b64encode(signature).decode()
    }

    # Show JSON in text box
    txt_license.delete("1.0", tk.END)
    txt_license.insert(tk.END, json.dumps(license_data, indent=4))

# --- UI Setup ---
root = tk.Tk()
root.title("License Generator (RSA, MAC only)")

canvas = tk.Canvas(root)
scrollbar = tk.Scrollbar(root, orient="vertical", command=canvas.yview)
scroll_frame = tk.Frame(canvas)

scroll_frame.bind(
    "<Configure>",
    lambda e: canvas.configure(
        scrollregion=canvas.bbox("all")
    )
)

canvas.create_window((0, 0), window=scroll_frame, anchor="nw")
canvas.configure(yscrollcommand=scrollbar.set)

canvas.pack(side="left", fill="both", expand=True)
scrollbar.pack(side="right", fill="y")

# --- Widgets inside scroll_frame ---
btn_keys = tk.Button(scroll_frame, text="Generate RSA Keys", command=generate_keypair)
btn_keys.grid(row=0, column=0, columnspan=2, pady=5)

tk.Label(scroll_frame, text="Device MAC Address:").grid(row=1, column=0, sticky="e", pady=5)
entry_mac = tk.Entry(scroll_frame, width=30)
entry_mac.grid(row=1, column=1, pady=5)

btn_license = tk.Button(scroll_frame, text="Generate License", command=sign_license)
btn_license.grid(row=2, column=0, columnspan=2, pady=10)

tk.Label(scroll_frame, text="🔑 Private Key (KEEP SAFE)").grid(row=3, column=0, columnspan=2)
txt_private = scrolledtext.ScrolledText(scroll_frame, width=70, height=10)
txt_private.grid(row=4, column=0, columnspan=2, pady=5)

tk.Label(scroll_frame, text="🌍 Public Key (Embed in ESP32)").grid(row=5, column=0, columnspan=2)
txt_public = scrolledtext.ScrolledText(scroll_frame, width=70, height=10)
txt_public.grid(row=6, column=0, columnspan=2, pady=5)

tk.Label(scroll_frame, text="📜 License JSON (Give to Customer)").grid(row=7, column=0, columnspan=2)
txt_license = scrolledtext.ScrolledText(scroll_frame, width=70, height=12)
txt_license.grid(row=8, column=0, columnspan=2, pady=5)

root.mainloop()