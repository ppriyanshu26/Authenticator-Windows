import customtkinter as ctk
import pyperclip, os, hashlib, config, cv2, aes, io, json, time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, unquote
import numpy as np
from PIL import Image, ImageFilter

def read_qr_from_bytes(image_bytes):
    try:
        img = cv2.imdecode(np.frombuffer(image_bytes, np.uint8), cv2.IMREAD_COLOR)
        if img is None: return None
        data, _, _ = cv2.QRCodeDetector().detectAndDecode(img)
        return data
    except: return None

def load_otps_from_decrypted(otps):
    return sorted(otps, key=lambda x: x.get('platform', '').lower())

def clean_uri(uri):
    if not uri or "otpauth://" not in uri: return "", "", ""
    parsed = urlparse(uri)
    query = parse_qs(parsed.query)
    label_issuer, _, username = (lambda l: (l.split(':')[0], None, l.split(':')[1]) if ':' in l else (l, None, l))(unquote(parsed.path.split('/')[-1]))
    if label_issuer != (qi := query.get("issuer", [label_issuer])[0]):
        query['issuer'] = [label_issuer]
    return urlunparse(parsed._replace(query=urlencode(query, doseq=True))), label_issuer, username

def generate_id(platform, secret, salt=None):
    salt = salt or str(time.time())
    return hashlib.sha256(f"{platform}{secret}{salt}".encode()).hexdigest()

def save_otps_encrypted(otp_list, key):
    encrypted = aes.Crypto(key).encrypt_aes(json.dumps(otp_list))
    with open(config.ENCODED_FILE, 'w') as f:
        f.write(encrypted)

def decode_encrypted_file():
    if not config.decrypt_key or not os.path.exists(config.ENCODED_FILE): return []
    crypto = aes.Crypto(config.decrypt_key)
    try:
        with open(config.ENCODED_FILE, 'r') as f:
            if (content := f.read().strip()):
                data = json.loads(crypto.decrypt_aes(content))
                return data if isinstance(data, list) else []
    except: pass
    return []

def extract_secret_from_uri(uri):
    try:
        return parse_qs(urlparse(uri).query).get('secret', [None])[0]
    except: return None

def load_image_paths():
    if not os.path.exists(config.IMAGE_PATH_FILE): return {}
    try:
        with open(config.IMAGE_PATH_FILE, 'r') as f:
            return json.loads(content) if (content := f.read().strip()) else {}
    except: return {}

def save_image_path(cred_id, enc_img_path):
    try:
        paths = load_image_paths()
        paths[cred_id] = enc_img_path
        with open(config.IMAGE_PATH_FILE, 'w') as f:
            f.write(json.dumps(paths))
        return True
    except: return False

def get_image_path(cred_id):
    return load_image_paths().get(cred_id)

def delete_image_path(cred_id):
    try:
        paths = load_image_paths()
        if cred_id in paths:
            del paths[cred_id]
            with open(config.IMAGE_PATH_FILE, 'w') as f:
                f.write(json.dumps(paths))
    except: pass
    return True

def get_qr_image(cred_id, key, blur=True):
    enc_img_path = get_image_path(cred_id)
    if not enc_img_path or not os.path.exists(enc_img_path): return None
    try:
        img_bytes = aes.Crypto(key).decrypt_bytes(open(enc_img_path, 'rb').read())
        img = Image.open(io.BytesIO(img_bytes))
        if img.mode != "RGBA": img = img.convert("RGBA")
        img = img.resize((200, 200), Image.Resampling.LANCZOS)
        return img.filter(ImageFilter.GaussianBlur(radius=15)) if blur else img
    except: return None

def save_password(password):
    try:
        hashed = hashlib.sha256(password.encode()).hexdigest()
        pw_path = os.path.join(config.APP_FOLDER, "password.hash")
        with open(pw_path, "w") as f: f.write(hashed)
        try: os.chmod(pw_path, 0o600)
        except: pass
        return True
    except: return False

def get_stored_password():
    try:
        return open(os.path.join(config.APP_FOLDER, "password.hash"), "r").read().strip()
    except: return None

def delete_credential(cred_id, key):
    otps = decode_encrypted_file()
    if not any(c['id'] == cred_id for c in otps): return False
    
    enc_img_path = get_image_path(cred_id)
    if enc_img_path and os.path.exists(enc_img_path):
        try: os.remove(enc_img_path)
        except: pass
    delete_image_path(cred_id)
    
    save_otps_encrypted([c for c in otps if c['id'] != cred_id], key)
    return True

def bind_enter(root, button):
    root.unbind_all("<Return>")
    root.bind_all("<Return>", lambda _: button.invoke())

def truncate(text, max_len, suffix="..."):
    return f"{text[:max_len]}{suffix}" if len(text) > max_len else text

# Legacy aliases for backward compatibility
def copy_and_toast(var, root):
    pyperclip.copy(var.get())
    if config.toast_label: config.toast_label.destroy()
    config.toast_label = ctk.CTkLabel(root, text="✅ Copied to clipboard", fg_color="#22cc22", text_color="white", font=("Segoe UI", 12), corner_radius=8, padx=12, pady=6)
    config.toast_label.place(relx=0.5, rely=0.9, anchor='s')
    root.after(1500, lambda: config.toast_label.destroy() if config.toast_label else None)

truncate_platform_name = lambda name: truncate(name, 20)
truncate_username = lambda username: truncate(username, 35)