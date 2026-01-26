import customtkinter as ctk
import hashlib, os, config, utils, aes

def reencrypt_all_data(old_key, new_key):
    config.decrypt_key = old_key
    otps = utils.decode_encrypted_file()
    if not otps and os.path.exists(config.ENCODED_FILE):
        config.decrypt_key = None
        return False
    
    try:
        old_crypto, new_crypto = aes.Crypto(old_key), aes.Crypto(new_key)
        for cred_id, enc_img_path in utils.load_image_paths().items():
            if enc_img_path and os.path.exists(enc_img_path):
                try:
                    new_enc_data = new_crypto.encrypt_bytes(old_crypto.decrypt_bytes(open(enc_img_path, 'rb').read()))
                    open(enc_img_path, 'wb').write(new_enc_data)
                except Exception as e:
                    print(f"Warning: Failed to re-encrypt image {enc_img_path}: {e}")
        
        utils.save_otps_encrypted(otps, new_key)
        config.decrypt_key = new_key
        return True
    except Exception as e:
        print(f"Re-encryption failed: {e}")
        config.decrypt_key = None
        return False

def make_pwd_entry(parent, label):
    ctk.CTkLabel(parent, text=label, text_color="white", font=("Segoe UI", 14, "bold")).pack(pady=(15, 5))
    row = ctk.CTkFrame(parent, fg_color="transparent")
    entry = ctk.CTkEntry(row, show="*", font=("Segoe UI", 14), justify="center", width=210, height=40)
    entry.pack(side="left")
    entry.is_hidden = True
    toggle = ctk.CTkLabel(row, text="👁️", width=48, height=44, fg_color="#444", text_color="white", corner_radius=10, font=("Segoe UI Emoji", 20))
    toggle.bind("<Button-1>", lambda _, e=entry, t=toggle: (e.configure(show=""), setattr(e, 'is_hidden', False), t.configure(text="🙈")) if e.is_hidden else (e.configure(show="*"), setattr(e, 'is_hidden', True), t.configure(text="👁️")))
    toggle.pack(side="left", padx=(8,0))
    row.pack()
    return entry

def reset_password_full_ui(root, otp_entries, build_main_ui_callback):
    for w in root.winfo_children(): w.destroy()
    
    frame = ctk.CTkFrame(root, fg_color="#1e1e1e", corner_radius=0)
    frame.pack(expand=True, fill="both")
    root.unbind_all("<Return>")
    root.unbind_all("<Escape>")
    
    ctk.CTkLabel(frame, text="🔐 Reset Password", font=("Segoe UI", 20, "bold"), text_color="white").pack(pady=(40, 30))
    
    curr_entry = make_pwd_entry(frame, "Enter current password:")
    new_entry = make_pwd_entry(frame, "New password:")
    conf_entry = make_pwd_entry(frame, "Confirm new password:")
    curr_entry.focus_set()
    
    def show_toast(msg, err=False):
        if config.toast_label: config.toast_label.destroy()
        config.toast_label = ctk.CTkLabel(root, text=msg, fg_color="#ff4d4d" if err else "#22cc22", text_color="white", font=("Segoe UI", 14), corner_radius=10, padx=16, pady=12)
        config.toast_label.place(relx=0.5, rely=0.9, anchor='s')
        root.after(2500, lambda: config.toast_label.destroy() if config.toast_label else None)
    
    def perform_reset():
        curr_pwd = curr_entry.get()
        new_pwd = new_entry.get()
        
        if hashlib.sha256(curr_pwd.encode()).hexdigest() != utils.get_stored_password():
            show_toast("❌ Incorrect current password", err=True)
        elif new_pwd != conf_entry.get():
            show_toast("❌ New passwords do not match", err=True)
        elif len(new_pwd) < 8:
            show_toast("❌ Password too short (min 8 chars)", err=True)
        elif reencrypt_all_data(curr_pwd, new_pwd):
            utils.save_password(new_pwd)
            config.decrypt_key = new_pwd
            otp_entries[:] = utils.load_otps_from_decrypted(utils.decode_encrypted_file())
            show_toast("✅ Password reset successfully")
            root.after(1500, lambda: build_main_ui_callback(root, otp_entries))
        else:
            show_toast("❌ Failed to re-encrypt data", err=True)
    
    def go_back():
        otp_entries[:] = utils.load_otps_from_decrypted(utils.decode_encrypted_file())
        build_main_ui_callback(root, otp_entries)
    
    btn_frame = ctk.CTkFrame(frame, fg_color="transparent")
    btn_frame.pack(pady=30)
    
    ctk.CTkButton(btn_frame, text="✅ Submit", command=perform_reset, font=("Segoe UI", 13, "bold"), width=120, height=40, fg_color="#444").pack(side="left", padx=5)
    ctk.CTkButton(btn_frame, text="❌ Cancel", command=go_back, font=("Segoe UI", 13, "bold"), width=120, height=40, fg_color="#3d3d3d").pack(side="left", padx=5)
    
    safe_trigger = lambda check, fn: fn() if all(w.winfo_exists() for w in check) else None
    root.bind("<Return>", lambda _: safe_trigger([curr_entry, new_entry, conf_entry], perform_reset))
    root.bind("<Escape>", lambda _: safe_trigger([frame], go_back))
