import os, csv, utils
from tkinter import messagebox

def export_to_csv():
    otps = utils.decode_encrypted_file()
    if not otps:
        return False, "No data to export"
    
    try:
        desktop = os.path.expanduser("~/Desktop")
        filepath = os.path.join(desktop, "CipherAuth.csv")
        
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["Platform", "TOTP URL"])
            for platform, uri, _ in otps:
                writer.writerow([platform, uri])
                
        return True, f"Exported to {filepath}"
    except Exception as e:
        return False, str(e)

def handle_download():
    success, msg = export_to_csv()
    if success:
        messagebox.showinfo("Export Successful", msg)
    else:
        messagebox.showerror("Export Failed", msg)
