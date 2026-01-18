import os, sys

if sys.platform == "win32":
    local_appdata = os.getenv("LOCALAPPDATA")
    pkg_family = os.getenv("APPX_PACKAGE_FAMILY_NAME") or os.getenv("PACKAGE_FAMILY_NAME")
    if local_appdata and pkg_family:
        BASE_APP_DIR = os.path.join(local_appdata, "Packages", pkg_family, "LocalState")
    else:
        BASE_APP_DIR = local_appdata
elif sys.platform == "darwin":
    BASE_APP_DIR = os.path.expanduser("~/Library/Application Support")
elif sys.platform.startswith("linux"):
    BASE_APP_DIR = os.path.expanduser("~/.local/share")  
else:
    BASE_APP_DIR = os.getcwd() 

APP_FOLDER = os.path.join(BASE_APP_DIR, "CipherAuth")
os.makedirs(APP_FOLDER, exist_ok=True)
ENCODED_FILE = os.path.join(APP_FOLDER, "creds.txt")

decrypt_key = None
toast_label = None
inner_frame = None
popup_window = None
frames = []
