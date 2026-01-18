import tkinter as tk
from tkinter import filedialog
import customtkinter as ctk
import os, time, hashlib, config, utils, aes, qrcode, io, pyotp

def add_credential(platform, username=None, secret=None, qr_path=None, key=None):
    crypto = aes.Crypto(key)
    uri = None
    enc_img_path = "NONE"

    if qr_path and os.path.exists(qr_path):
        with open(qr_path, 'rb') as f:
            original_data = f.read()
        
        uri = utils.read_qr_from_bytes(original_data)
        if not uri:
            return False, "Could not read QR code from image"
        
        qr_folder = os.path.join(config.APP_FOLDER, "qrs")
        os.makedirs(qr_folder, exist_ok=True)
        
        enc_img_data = crypto.encrypt_bytes(original_data)
        safe_name = hashlib.md5(f"{platform}{time.time()}".encode()).hexdigest()
        enc_img_path = os.path.join(qr_folder, f"{safe_name}.enc")
        
        with open(enc_img_path, 'wb') as f:
            f.write(enc_img_data)
    elif secret and username:
        try:
            secret = secret.replace(" ", "").upper()
            pyotp.TOTP(secret).now()
            uri = pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name=platform)
            
            qr = qrcode.QRCode(version=1, box_size=10, border=5)
            qr.add_data(uri)
            qr.make(fit=True)
            img = qr.make_image(fill_color="black", back_color="white")
            
            img_byte_arr = io.BytesIO()
            img.save(img_byte_arr, format='PNG')
            qr_bytes = img_byte_arr.getvalue()
            
            qr_folder = os.path.join(config.APP_FOLDER, "qrs")
            os.makedirs(qr_folder, exist_ok=True)
            
            enc_img_data = crypto.encrypt_bytes(qr_bytes)
            safe_name = hashlib.md5(f"{platform}{time.time()}".encode()).hexdigest()
            enc_img_path = os.path.join(qr_folder, f"{safe_name}.enc")
            
            with open(enc_img_path, 'wb') as f:
                f.write(enc_img_data)
        except Exception as e:
            return False, f"Error generating QR for manual entry: {e}"
    else:
        return False, "Provide either a QR code or Secret Key + Username"
    
    line_to_encrypt = f"{platform}|{uri}|{enc_img_path}"
    encrypted_line = crypto.encrypt_aes(line_to_encrypt)
    
    with open(config.ENCODED_FILE, 'a') as f:
        f.write(encrypted_line + "\n")
    
    return True, "Credential added successfully"

def edit_credentials_full_ui(root, build_main_ui_callback):
    for widget in root.winfo_children():
        widget.destroy()
    
    frame = ctk.CTkFrame(root, fg_color="#1e1e1e", corner_radius=0)
    frame.pack(expand=True, fill="both", padx=20, pady=20)
    
    root.unbind_all("<Return>")
    root.unbind_all("<Escape>")
    
    ctk.CTkLabel(frame, text="➕ Add New Credential", font=("Segoe UI", 18, "bold"), text_color="white").pack(pady=(10, 20))
    
    ctk.CTkLabel(frame, text="Platform Name:", text_color="white", font=("Segoe UI", 12, "bold")).pack(anchor="w")
    platform_entry = ctk.CTkEntry(frame, font=("Segoe UI", 12), height=35)
    platform_entry.pack(fill="x", pady=(0, 15))

    ctk.CTkLabel(frame, text="Username (for manual entry):", text_color="white", font=("Segoe UI", 12, "bold")).pack(anchor="w")
    user_entry = ctk.CTkEntry(frame, font=("Segoe UI", 12), height=35)
    user_entry.pack(fill="x", pady=(0, 15))

    ctk.CTkLabel(frame, text="Secret Key (for manual entry):", text_color="white", font=("Segoe UI", 12, "bold")).pack(anchor="w")
    secret_entry = ctk.CTkEntry(frame, font=("Segoe UI", 12), height=35)
    secret_entry.pack(fill="x", pady=(0, 15))
    
    ctk.CTkLabel(frame, text="Or Select QR Code Image:", text_color="white", font=("Segoe UI", 12, "bold")).pack(anchor="w")
    path_frame = ctk.CTkFrame(frame, fg_color="transparent")
    path_frame.pack(fill="x", pady=(0, 20))
    
    path_entry = ctk.CTkEntry(path_frame, font=("Segoe UI", 12), height=35)
    path_entry.pack(side="left", fill="x", expand=True)
    
    def browse_file():
        filename = filedialog.askopenfilename(title="Select QR Code", filetypes=[("Image files", "*.png *.jpg *.jpeg *.bmp")])
        if filename:
            path_entry.delete(0, tk.END)
            path_entry.insert(0, filename)
            
    ctk.CTkButton(path_frame, text="📁 Browse", width=80, height=35, command=browse_file, fg_color="#444", text_color="white", hover_color="#555", font=("Segoe UI", 11)).pack(side="right", padx=(10, 0))
    
    def show_toast(message, is_error=False):
        if config.toast_label:
            config.toast_label.destroy()
        color = "#ff4d4d" if is_error else "#22cc22"
        config.toast_label = ctk.CTkLabel(root, text=message, fg_color=color, text_color="white",
                               font=("Segoe UI", 12), corner_radius=10, padx=16, pady=12)
        config.toast_label.place(relx=0.5, rely=0.9, anchor='s')
        root.after(2500, lambda: config.toast_label.destroy() if config.toast_label else None)
    
    def go_back():
        new_entries = utils.load_otps_from_decrypted(utils.decode_encrypted_file())
        build_main_ui_callback(root, new_entries)
    
    def save_cred():
        platform = platform_entry.get().strip()
        username = user_entry.get().strip()
        secret = secret_entry.get().strip()
        path = path_entry.get().strip()
        
        if not platform:
            show_toast("❌ Platform name is required", is_error=True)
            return
        
        success, msg = add_credential(platform, username, secret, path, config.decrypt_key)
        if success:
            show_toast("✅ " + msg)
            root.after(1500, go_back)
        else:
            show_toast("❌ " + msg, is_error=True)
    
    button_frame = ctk.CTkFrame(frame, fg_color="transparent")
    button_frame.pack(pady=20)
    
    save_btn = ctk.CTkButton(button_frame, text="✅ Save", height=40, command=save_cred, 
                            fg_color="#444", text_color="white", hover_color="#666", font=("Segoe UI", 12, "bold"), width=120)
    save_btn.pack(side="left", padx=5)
    
    cancel_btn = ctk.CTkButton(button_frame, text="❌ Cancel", height=40, command=go_back,
                              fg_color="#3d3d3d", text_color="white", hover_color="#4d4d4d", font=("Segoe UI", 12, "bold"), width=120)
    cancel_btn.pack(side="left", padx=5)
    
    platform_entry.focus()
    
    def safe_save_cred(event=None):
        try:
            if platform_entry.winfo_exists() and user_entry.winfo_exists() and secret_entry.winfo_exists() and path_entry.winfo_exists():
                save_cred()
        except Exception:
            pass
    
    def safe_go_back(event=None):
        try:
            if frame.winfo_exists():
                go_back()
        except Exception:
            pass
    
    root.bind("<Return>", safe_save_cred)
    root.bind("<Escape>", safe_go_back)


def edit_credentials_popup(parent, root, build_main_ui_callback):
    edit_credentials_full_ui(root, build_main_ui_callback)


def show_delete_confirmation_screen(root, display_name, uri, enc_img_path, otp_entries, build_main_ui_callback):
    """Display a full-screen delete confirmation with Enter/Escape bindings"""
    for widget in root.winfo_children():
        widget.destroy()
    
    root.unbind_all("<Return>")
    root.unbind_all("<Escape>")
    
    # Extract username from URI
    cleaned_uri, issuer, username = utils.clean_uri(uri)
    
    frame = ctk.CTkFrame(root, fg_color="#1e1e1e", corner_radius=0)
    frame.pack(expand=True, fill="both", padx=40, pady=40)
    
    content_frame = ctk.CTkFrame(frame, fg_color="transparent")
    content_frame.pack(expand=True)
    
    # Warning icon and title
    ctk.CTkLabel(content_frame, text="⚠️", font=("Segoe UI", 80), text_color="#ff6b6b").pack(pady=(0, 15))
    ctk.CTkLabel(content_frame, text="Delete Credential?", font=("Segoe UI", 32, "bold"), text_color="#ff6b6b").pack(pady=(0, 10))
    
    # Separator line
    ctk.CTkFrame(content_frame, height=2, fg_color="#444").pack(fill="x", pady=20)
    
    # Credential details with highlight
    name_frame = ctk.CTkFrame(content_frame, fg_color="#2b2b2b", corner_radius=8)
    name_frame.pack(fill="x", pady=(0, 30), padx=20)
    ctk.CTkLabel(name_frame, text="Credential to Delete:", font=("Segoe UI", 11, "bold"), text_color="#aaaaaa").pack(anchor="w", padx=15, pady=(10, 5))
    ctk.CTkLabel(name_frame, text=display_name, font=("Segoe UI", 16, "bold"), text_color="#ffaa00").pack(anchor="w", padx=15, pady=(0, 5))
    ctk.CTkLabel(name_frame, text=f"Username: {username}", font=("Segoe UI", 12), text_color="#cccccc").pack(anchor="w", padx=15, pady=(0, 10))
    
    # Warning message
    ctk.CTkLabel(content_frame, text="⚠️  This action cannot be undone.", font=("Segoe UI", 13), text_color="#ff8866").pack(pady=(0, 20))
    
    # Button frame
    button_frame = ctk.CTkFrame(content_frame, fg_color="transparent")
    button_frame.pack(pady=10)
    
    def perform_delete():
        """Execute the delete operation"""
        if utils.delete_credential(display_name, uri, config.decrypt_key, enc_img_path):
            otp_entries[:] = utils.load_otps_from_decrypted(utils.decode_encrypted_file())
            build_main_ui_callback(root, otp_entries)
    
    def cancel_delete():
        """Return to main screen without deleting"""
        build_main_ui_callback(root, otp_entries)
    
    # Delete button (styled in red) - Left side
    delete_btn = ctk.CTkButton(button_frame, text="🗑️  Delete", height=55, width=180, 
                               command=perform_delete, 
                               fg_color="#d32f2f", text_color="white", hover_color="#b71c1c", 
                               font=("Segoe UI", 14, "bold"), corner_radius=10)
    delete_btn.pack(side="left", padx=15)
    
    # Cancel button - Right side
    cancel_btn = ctk.CTkButton(button_frame, text="✖️  Cancel", height=55, width=180,
                               command=cancel_delete,
                               fg_color="#3d3d3d", text_color="white", hover_color="#4d4d4d",
                               font=("Segoe UI", 14, "bold"), corner_radius=10)
    cancel_btn.pack(side="left", padx=15)
    
    # Keyboard shortcuts hint
    hint_frame = ctk.CTkFrame(content_frame, fg_color="transparent")
    hint_frame.pack(pady=30)
    ctk.CTkLabel(hint_frame, text="⌨️  Keyboard Shortcuts:", font=("Segoe UI", 11, "bold"), text_color="#888").pack()
    ctk.CTkLabel(hint_frame, text="ENTER to Delete  •  ESC to Cancel", font=("Segoe UI", 10), text_color="#666").pack()
    
    spacer2 = ctk.CTkFrame(frame, fg_color="transparent")
    spacer2.pack(expand=True)
    
    # Key bindings
    def safe_delete(event=None):
        try:
            if content_frame.winfo_exists():
                perform_delete()
        except Exception:
            pass
    
    def safe_cancel(event=None):
        try:
            if content_frame.winfo_exists():
                cancel_delete()
        except Exception:
            pass
    
    root.bind("<Return>", safe_delete)
    root.bind("<Escape>", safe_cancel)
    
    # Set focus to cancel button (safer default)
    cancel_btn.focus()
