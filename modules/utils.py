import hashlib
from zipfile import ZipFile
import os
from colorama import init, Fore, Style
init(autoreset=True)
def hash_file(filepath):
    sha256 = hashlib.sha256()
    try:
        with open(filepath, 'rb') as f:
            while chunk := f.read(4096):
                sha256.update(chunk)
        return sha256.hexdigest()
    except FileNotFoundError:
        return None

def compress_report(report_file, hash_value,output_dir):
    zip_name = f"{output_dir}/forensic_report.zip"
    hash_file_path = f"{output_dir}/report_hash.txt"

    # Save the hash to a file
    with open(hash_file_path, "w") as f:
        f.write(f"SHA-256: {hash_value}\n")

    # Create the ZIP file
    with ZipFile(zip_name, 'w') as zipf:
        zipf.write(report_file, os.path.basename(report_file))
        zipf.write(hash_file_path, os.path.basename(hash_file_path))

    # Clean up intermediate hash file
    os.remove(hash_file_path)

    print(Fore.MAGENTA + Style.BRIGHT + f"[✔] Report and hash compressed into {zip_name}")
    print(Fore.BLUE + Style.BRIGHT + f"*"*20)
