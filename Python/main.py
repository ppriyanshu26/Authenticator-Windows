import tkinter as tk
import customtkinter as ctk
import pyotp, sys, time, hashlib, ctypes, config
import utils, reset_handler, creds_handler, export_handler

if sys.platform == "win32":
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

def lock_app(root, otp_entries):
    for w in root.winfo_children(): w.destroy()
    build_lock_screen(root, otp_entries)

def open_popup(func, title="Popup", size="370x300", *args, **kwargs):
    if config.popup_window and config.popup_window.winfo_exists():
        config.popup_window.lift()
        config.popup_window.focus_force()
        return config.popup_window
    
    popup = ctk.CTkToplevel(root)
    config.popup_window = popup
    popup.title(title)
    popup.configure(fg_color="#1e1e1e")
    popup.transient(root)
    popup.grab_set()
    
    popup.geometry(size)
    root_x, root_y = root.winfo_x(), root.winfo_y()
    root_w, root_h = root.winfo_width(), root.winfo_height()
    win_w, win_h = map(int, size.split("x"))
    popup.geometry(f"{win_w}x{win_h}+{root_x + root_w//2 - win_w//2}+{root_y + root_h//2 - win_h//2}")
    
    popup.protocol("WM_DELETE_WINDOW", lambda: (setattr(config, 'popup_window', None), popup.destroy()))
    func(popup, *args, **kwargs)
    return popup

def render_otp_list(root, otp_entries, query=""):
    for w in config.inner_frame.winfo_children(): w.destroy()
    config.frames.clear()
    
    query = query.lower().strip()
    filtered = [e for e in otp_entries if e.get('platform', '').lower().startswith(query)] if query else otp_entries

    if not filtered:
        msg = "🔍 No matches found" if query else "⚠️ No OTPs Loaded"
        color = "#888" if query else "red"
        ctk.CTkLabel(config.inner_frame, text=msg, font=("Segoe UI", 14, "bold"), text_color=color).pack(pady=20)
        return
    
    for cred in filtered:
        platform, username, secret, cred_id = cred.get('platform', 'Unknown'), cred.get('username', 'Unknown'), cred.get('secretcode', ''), cred.get('id')
        enc_img_path = utils.get_image_path(cred_id)
        
        if not secret: continue
        totp_obj = pyotp.TOTP(secret)
        
        card = ctk.CTkFrame(config.inner_frame, fg_color="#2b2b2b", corner_radius=10)
        card.pack(fill="x", padx=12, pady=10)
        
        header = ctk.CTkFrame(card, fg_color="transparent")
        header.pack(fill="x", padx=10, pady=(10, 0))
        
        ctk.CTkLabel(header, text=utils.truncate_platform_name(platform), font=("Segoe UI", 14, "bold"), text_color="#ffffff").pack(side="left")
        
        del_btn = ctk.CTkButton(header, text="Delete", width=60, height=24, font=("Segoe UI", 11), fg_color="transparent", text_color="#ff4d4d", hover_color="#3d3d3d", command=lambda c=cred: creds_handler.show_delete_confirmation_screen(root, c, otp_entries, build_main_ui))
        del_btn.pack(side="right", padx=(5, 0))
        
        qr_btn = None
        if enc_img_path:
            qr_btn = ctk.CTkButton(header, text="View QR", width=60, height=24, font=("Segoe UI", 11), fg_color="#444", text_color="white", hover_color="#555")
            qr_btn.pack(side="right")
        
        ctk.CTkLabel(card, text=utils.truncate_username(username), font=("Segoe UI", 11), text_color="#aaaaaa", anchor="w").pack(fill="x", padx=10)
        
        bottom = ctk.CTkFrame(card, fg_color="transparent")
        bottom.pack(fill="x", padx=10, pady=(5, 10))
        
        code_var = tk.StringVar()
        ctk.CTkLabel(bottom, textvariable=code_var, font=("Courier", 20, "bold"), text_color="#00ffcc").pack(side="left")
        
        time_var = tk.StringVar()
        time_label = ctk.CTkLabel(bottom, textvariable=time_var, font=("Segoe UI", 12, "bold"), text_color="#00ffcc")
        time_label.pack(side="left", padx=(10, 0))
        
        ctk.CTkButton(bottom, text="Copy", width=60, height=28, font=("Segoe UI", 11), fg_color="#444", text_color="white", hover_color="#666", command=lambda v=code_var: utils.copy_and_toast(v, root)).pack(side="right")
        
        config.frames.append({"totp": totp_obj, "code_var": code_var, "time_var": time_var, "time_label": time_label})
        
        if qr_btn:
            qr_frame = ctk.CTkFrame(card, fg_color="transparent")
            
            def show_qr(f, cid=cred_id, btn=qr_btn):
                for w in f.winfo_children(): w.destroy()
                if (img := utils.get_qr_image(cid, config.decrypt_key, blur=True)):
                    img_ctk = ctk.CTkImage(light_image=img, dark_image=img, size=(200, 200))
                    lbl = ctk.CTkLabel(f, image=img_ctk, text="", cursor="hand2")
                    lbl.image, lbl.is_revealed = img_ctk, False
                    lbl.pack()
                    hint = ctk.CTkLabel(f, text="Tap to unblur QR", font=("Segoe UI", 12, "italic"), text_color="#888888")
                    hint.pack(pady=(2, 0))
                    lbl.bind("<Button-1>", lambda e, l=lbl, cid=cid, h=hint: toggle_qr_reveal(l, cid, h))
            
            def toggle_qr_reveal(lbl, cid, hint):
                lbl.is_revealed = not lbl.is_revealed
                if lbl.is_revealed:
                    if (img := utils.get_qr_image(cid, config.decrypt_key, blur=False)):
                        img_ctk = ctk.CTkImage(light_image=img, dark_image=img, size=(200, 200))
                        lbl.configure(image=img_ctk)
                        lbl.image = img_ctk
                        hint.configure(text="Tap to blur QR")
                else:
                    if (img := utils.get_qr_image(cid, config.decrypt_key, blur=True)):
                        img_ctk = ctk.CTkImage(light_image=img, dark_image=img, size=(200, 200))
                        lbl.configure(image=img_ctk)
                        lbl.image = img_ctk
                        hint.configure(text="Tap to unblur QR")
            
            qr_btn.configure(command=lambda f=qr_frame, btn=qr_btn: (f.pack_forget() if f.winfo_viewable() else (f.pack(fill="x", pady=(0, 10)), show_qr(f)), btn.configure(text="Hide QR" if f.winfo_viewable() else "View QR")))

def update_totps(root):
    for entry in config.frames:
        try:
            totp, code_var, time_var, time_label = entry["totp"], entry["code_var"], entry["time_var"], entry["time_label"]
            code, time_left = totp.now(), 30 - int(time.time()) % 30
            code_var.set(code)
            time_var.set(f"{time_left}s")
            color = "#28db73" if time_left > 20 else "#ffcc00" if time_left > 10 else "#ff4d4d"
            time_label.configure(text_color=color)
        except (tk.TclError, ValueError): continue
    root.after(1000, lambda: update_totps(root))

def build_main_ui(root, otp_entries):
    for w in root.winfo_children(): w.destroy()
    
    top_bar = ctk.CTkFrame(root, fg_color="#1e1e1e", corner_radius=0)
    top_bar.pack(side="top", fill="x", padx=10)
    
    search_entry = ctk.CTkEntry(top_bar, font=("Segoe UI", 13), placeholder_text="Type to search", height=35, placeholder_text_color="#888")
    search_entry.pack(side="left", fill="x", expand=True, padx=(0, 10), pady=10)
    search_entry.bind("<KeyRelease>", lambda _: render_otp_list(root, otp_entries, search_entry.get()))
    
    ctk.CTkButton(top_bar, text="🔒 Lock", width=80, height=35, font=("Segoe UI", 12, "bold"), fg_color="#444", text_color="white", hover_color="#666", command=lambda: lock_app(root, otp_entries)).pack(side="right", pady=10)
    
    ctk.CTkFrame(root, height=2, fg_color="#333").pack(fill="x")
    
    outer_frame = ctk.CTkFrame(root, fg_color="#1e1e1e", corner_radius=0)
    outer_frame.pack(fill="both", expand=True)
    
    footer = ctk.CTkFrame(outer_frame, fg_color="#1e1e1e", corner_radius=0)
    footer.pack(side="bottom", fill="x")
    
    for btn_text, cmd in [("🔄 Reset", lambda: reset_handler.reset_password_full_ui(root, otp_entries, build_main_ui)), ("➕ Add Creds", lambda: creds_handler.edit_credentials_full_ui(root, build_main_ui)), ("📥 Download", lambda: export_handler.handle_download(root))]:
        ctk.CTkButton(footer, text=btn_text, font=("Segoe UI", 12), fg_color="#2b2b2b", text_color="white", hover_color="#3d3d3d", height=45, corner_radius=0, command=cmd).pack(side="left", fill="x", expand=True)
    
    config.inner_frame = ctk.CTkScrollableFrame(outer_frame, fg_color="#1e1e1e", corner_radius=0)
    config.inner_frame.pack(fill="both", expand=True)
    
    render_otp_list(root, otp_entries)
    if otp_entries: update_totps(root)

def make_pwd_entry(parent, placeholder):
    row = ctk.CTkFrame(parent, fg_color="transparent")
    entry = ctk.CTkEntry(row, show="*", font=("Segoe UI",14), width=210, placeholder_text=placeholder, height=40)
    entry.pack(side="left")
    entry.is_hidden = True
    toggle = ctk.CTkLabel(row, text="👁️", width=48, height=44, fg_color="#444", text_color="white", corner_radius=10, font=("Segoe UI Emoji", 20))
    toggle.bind("<Button-1>", lambda _, e=entry, t=toggle: (e.configure(show=""), setattr(e, 'is_hidden', False), t.configure(text="🙈")) if e.is_hidden else (e.configure(show="*"), setattr(e, 'is_hidden', True), t.configure(text="👁️")))
    toggle.pack(side="left", padx=(8,0))
    row.pack(pady=(10,10))
    return entry

def build_create_password_screen(root, otp_entries):
    frame = ctk.CTkFrame(root, fg_color="#1e1e1e")
    frame.pack(expand=True, fill="both")
    root.unbind_all("<Return>")
    
    ctk.CTkLabel(frame, text="🔐 Create a Password", font=("Segoe UI",20,"bold"), text_color="white").pack(pady=(60,20))
    pwd1 = make_pwd_entry(frame, "Enter Password")
    pwd2 = make_pwd_entry(frame, "Confirm Password")
    pwd1.focus_set()
    
    error_label = ctk.CTkLabel(frame, text="", text_color="red", font=("Segoe UI",12))
    error_label.pack()
    
    def submit():
        if pwd1.get() != pwd2.get():
            error_label.configure(text="Passwords do not match.")
        elif len(pwd1.get()) < 8:
            error_label.configure(text="Password too short (min 8 chars).")
        else:
            utils.save_password(pwd1.get())
            frame.destroy()
            build_lock_screen(root, otp_entries)
    
    submit_btn = ctk.CTkButton(frame, text="Save & Continue", font=("Segoe UI",14, "bold"), width=250, height=45, command=submit)
    submit_btn.pack(pady=20)
    utils.bind_enter(root, submit_btn)

def check_password(root, entry, error_label, otp_entries, lock_frame):
    if hashlib.sha256((pwd := entry.get()).encode()).hexdigest() == utils.get_stored_password():
        config.decrypt_key = pwd
        lock_frame.destroy()
        otp_entries[:] = utils.load_otps_from_decrypted(utils.decode_encrypted_file())
        build_main_ui(root, otp_entries)
    else:
        error_label.configure(text="❌ Incorrect password")

def build_lock_screen(root, otp_entries):
    frame = ctk.CTkFrame(root, fg_color="#1e1e1e")
    frame.pack(expand=True, fill="both")
    root.unbind_all("<Return>")
    
    ctk.CTkLabel(frame, text="🔒 Enter Password", font=("Segoe UI",20,"bold"), text_color="white").pack(pady=(80,20))
    entry = make_pwd_entry(frame, "Password")
    entry.focus_set()
    
    error_label = ctk.CTkLabel(frame, text="", text_color="red", font=("Segoe UI",12))
    error_label.pack()
    
    unlock_btn = ctk.CTkButton(frame, text="Unlock", font=("Segoe UI",14, "bold"), width=250, height=45, command=lambda: check_password(root, entry, error_label, otp_entries, frame))
    unlock_btn.pack(pady=20)
    utils.bind_enter(root, unlock_btn)

if __name__ == "__main__":
    root = ctk.CTk()
    root.title("CipherAuth")
    root.geometry("420x550")
    root.configure(fg_color="#1e1e1e")
    root.resizable(False, False)

    otp_entries = []
    if utils.get_stored_password() is None:
        build_create_password_screen(root, otp_entries)
    else:
        build_lock_screen(root, otp_entries)

    root.mainloop()
