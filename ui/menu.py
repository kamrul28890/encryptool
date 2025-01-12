import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from utils.file_crypto import encrypt_file, decrypt_file
from utils.secure_delete import secure_delete
from cipher.caesar import caesar_encrypt, caesar_decrypt
from symmetric.aes import aes_encrypt, aes_decrypt
from hashing.sha256 import sha256_hash
from hashing.sha3 import sha3_hash
import datetime

# Global variables for history log
history_log = []

# Function to update the UI based on the selected operation type
def update_operation_type(event):
    operation = operation_var.get()

    # Reset all widgets
    model_dropdown.grid_forget()
    mode_label.grid_forget()
    encrypt_radio.grid_forget()
    decrypt_radio.grid_forget()
    key_label.grid_forget()
    key_input.grid_forget()
    input_label.grid_forget()
    input_text.grid_forget()
    output_label.grid_forget()
    output_text.grid_forget()
    file_button.grid_forget()
    batch_button.grid_forget()
    delete_button.grid_forget()
    run_button.grid_forget()

    # Show relevant widgets based on operation type
    if operation == "Text Encryption/Decryption":
        model_dropdown.grid(row=1, column=1, padx=10, pady=5)
        mode_label.grid(row=2, column=0, padx=10, pady=5, sticky=tk.W)
        encrypt_radio.grid(row=2, column=1, sticky=tk.W, padx=5)
        decrypt_radio.grid(row=2, column=1, sticky=tk.W, padx=80)
        key_label.grid(row=3, column=0, padx=10, pady=5, sticky=tk.W)
        key_input.grid(row=3, column=1, padx=10, pady=5)
        input_label.grid(row=4, column=0, padx=10, pady=5, sticky=tk.W)
        input_text.grid(row=4, column=1, padx=10, pady=5)
        output_label.grid(row=5, column=0, padx=10, pady=5, sticky=tk.W)
        output_text.grid(row=5, column=1, padx=10, pady=5)
        run_button.grid(row=6, column=0, padx=10, pady=10)
    elif operation == "File Encryption/Decryption":
        model_dropdown.grid(row=1, column=1, padx=10, pady=5)
        mode_label.grid(row=2, column=0, padx=10, pady=5, sticky=tk.W)
        encrypt_radio.grid(row=2, column=1, sticky=tk.W, padx=5)
        decrypt_radio.grid(row=2, column=1, sticky=tk.W, padx=80)
        key_label.grid(row=3, column=0, padx=10, pady=5, sticky=tk.W)
        key_input.grid(row=3, column=1, padx=10, pady=5)
        file_button.grid(row=4, column=1, padx=10, pady=10)
    elif operation == "Hashing":
        model_dropdown.grid(row=1, column=1, padx=10, pady=5)
        input_label.grid(row=3, column=0, padx=10, pady=5, sticky=tk.W)
        input_text.grid(row=3, column=1, padx=10, pady=5)
        output_label.grid(row=4, column=0, padx=10, pady=5, sticky=tk.W)
        output_text.grid(row=4, column=1, padx=10, pady=5)
        run_button.grid(row=5, column=0, padx=10, pady=10)
    elif operation == "Batch Processing":
        model_dropdown.grid(row=1, column=1, padx=10, pady=5)
        mode_label.grid(row=2, column=0, padx=10, pady=5, sticky=tk.W)
        encrypt_radio.grid(row=2, column=1, sticky=tk.W, padx=5)
        decrypt_radio.grid(row=2, column=1, sticky=tk.W, padx=80)
        key_label.grid(row=3, column=0, padx=10, pady=5, sticky=tk.W)
        key_input.grid(row=3, column=1, padx=10, pady=5)
        batch_button.grid(row=4, column=1, padx=10, pady=10)
    elif operation == "Secure Deletion":
        delete_button.grid(row=1, column=1, padx=10, pady=10)


# Function for text-based encryption/decryption
def run_cryptography():
    selected_model = model_var.get()
    operation = operation_var.get()
    mode = mode_var.get()  # Encrypt or Decrypt
    text = input_text.get("1.0", tk.END).strip()
    key = key_input.get().strip()
    output = ""

    try:
        if operation == "Text Encryption/Decryption":
            if selected_model == "AES":
                if len(key) not in [16, 24, 32]:
                    raise ValueError("AES key must be 16, 24, or 32 characters long!")
                if mode == "Encrypt":
                    output = aes_encrypt(text, key)
                else:
                    output = aes_decrypt(text, key)
            elif selected_model == "Caesar Cipher":
                shift = int(key) if key.isdigit() else 3
                if mode == "Encrypt":
                    output = caesar_encrypt(text, shift)
                else:
                    output = caesar_decrypt(text, shift)
            else:
                raise ValueError("Unsupported algorithm for encryption/decryption.")
        elif operation == "Hashing":
            if selected_model == "SHA-256":
                output = sha256_hash(text)
            elif selected_model == "SHA-3":
                output = sha3_hash(text)
            else:
                raise ValueError("Unsupported hashing algorithm.")

        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, output)

        # Log the operation
        log_entry = f"{datetime.datetime.now()} | Operation: {operation} | Mode: {mode if mode else 'N/A'} | Model: {selected_model} | Key: {key if key else 'N/A'}"
        history_log.append(log_entry)
    except Exception as e:
        messagebox.showerror("Error", str(e))


# Create the main application window
root = tk.Tk()
root.title("CryptoTool")
root.geometry("600x500")  # Default size
root.resizable(True, True)  # Allow resizing

# Variables
operation_var = tk.StringVar(value="Select Operation")
model_var = tk.StringVar(value="Select a model")
mode_var = tk.StringVar(value="Encrypt")  # Default mode is Encrypt

# Widgets Initialization
operation_label = tk.Label(root, text="Operation Type:")
operation_dropdown = ttk.Combobox(
    root,
    textvariable=operation_var,
    values=["Text Encryption/Decryption", "File Encryption/Decryption", "Hashing", "Batch Processing", "Secure Deletion"],
    state="readonly",
    width=30
)
operation_dropdown.bind("<<ComboboxSelected>>", update_operation_type)

model_label = tk.Label(root, text="Cryptography Model:")
model_dropdown = ttk.Combobox(
    root,
    textvariable=model_var,
    values=["AES", "Caesar Cipher", "SHA-256", "SHA-3"],
    state="readonly",
    width=20,
)
mode_label = tk.Label(root, text="Mode:")
encrypt_radio = tk.Radiobutton(root, text="Encrypt", variable=mode_var, value="Encrypt")
decrypt_radio = tk.Radiobutton(root, text="Decrypt", variable=mode_var, value="Decrypt")
key_label = tk.Label(root, text="Key:")
key_input = tk.Entry(root, width=30)
input_label = tk.Label(root, text="Input Text:")
input_text = tk.Text(root, height=5, width=40)
output_label = tk.Label(root, text="Output:")
output_text = tk.Text(root, height=5, width=40)
run_button = tk.Button(root, text="Run", command=run_cryptography, bg="lightblue")
file_button = tk.Button(root, text="Encrypt/Decrypt File", command=run_cryptography, bg="orange", width=20)
batch_button = tk.Button(root, text="Batch Encrypt/Decrypt", command=run_cryptography, bg="#87CEEB", width=20)
delete_button = tk.Button(root, text="Secure Delete Files", command=run_cryptography, bg="red", width=20)

# Grid Placement
operation_label.grid(row=0, column=0, padx=10, pady=5, sticky=tk.W)
operation_dropdown.grid(row=0, column=1, padx=10, pady=5)

# Run the application
root.mainloop()
