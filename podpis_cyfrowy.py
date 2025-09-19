import os
import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA3_256, SHAKE256, SHA256
import re
from datetime import datetime
import sys

TRNG_SEED_FILE = "merged_output.txt"  
SEED_BYTES_MIN = 8192                 
RSA_BITS = 2048

def _app_base_dir():
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    try:
        return os.path.dirname(os.path.abspath(__file__))
    except NameError:
        return os.getcwd()

BASE_DIR = _app_base_dir()
KEYS_DIR = os.path.join(BASE_DIR, "keys")
os.makedirs(KEYS_DIR, exist_ok=True)

def safe_slug_from_path(p: str) -> str:
    base = os.path.splitext(os.path.basename(p))[0]
    return re.sub(r'[^A-Za-z0-9_-]+', '_', base)[:64]

def safe_name_for_keys(p: str) -> str:
    base = os.path.splitext(os.path.basename(p))[0]  
    return re.sub(r'[^A-Za-z0-9._-]+', '_', base)[:128]

def generate_keys_for_file(randfunc, file_path: str, bits: int = RSA_BITS):
    slug = safe_name_for_keys(file_path)
    priv_path = os.path.join(KEYS_DIR, f"private_{slug}_key.pem")
    pub_path  = os.path.join(KEYS_DIR, f"public_{slug}_key.pem")

    key = RSA.generate(bits, randfunc=randfunc)
    priv, pub = key, key.publickey()

    with open(priv_path, "wb") as f:
        f.write(priv.export_key())
    try:
        os.chmod(priv_path, 0o600)
    except Exception:
        pass
    with open(pub_path, "wb") as f:
        f.write(pub.export_key())

    return priv, pub, priv_path, pub_path

def load_trng_seed(path: str, min_seed_bytes: int = SEED_BYTES_MIN) -> bytes:
    if not os.path.exists(path):
        raise FileNotFoundError(f"Nie znaleziono pliku TRNG: {path}")
    seed_bytes = bytearray()
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            s = line.strip()
            if len(s) == 8 and all(c in "01" for c in s):
                seed_bytes.append(int(s, 2))
                if len(seed_bytes) >= min_seed_bytes:
                    break
    if len(seed_bytes) < min_seed_bytes:
        raise ValueError(f"Za mało poprawnych bajtów TRNG: {len(seed_bytes)} < {min_seed_bytes}")
    return bytes(seed_bytes)

class TRNG_DRBG:
    def __init__(self, seed: bytes, domain: bytes = b"RSA-DRBG-v1"):
        self._shake = SHAKE256.new(seed + domain)

    def get_bytes(self, n: int) -> bytes:
        return self._shake.read(n)

def load_or_generate_keys(randfunc, bits: int = RSA_BITS):
    priv_path = os.path.join(KEYS_DIR, "private_key.pem")
    pub_path  = os.path.join(KEYS_DIR, "public_key.pem")

    if os.path.exists(priv_path) and os.path.exists(pub_path):
        with open(priv_path, "rb") as f:
            priv = RSA.import_key(f.read())
        with open(pub_path, "rb") as f:
            pub = RSA.import_key(f.read())
        return priv, pub

    key = RSA.generate(bits, randfunc=randfunc)
    priv, pub = key, key.publickey()

    with open(priv_path, "wb") as f:
        f.write(priv.export_key())
    try:
        os.chmod(priv_path, 0o600)
    except Exception:
        pass

    with open(pub_path, "wb") as f:
        f.write(pub.export_key())

    return priv, pub

def file_sha3_256(path: str) -> SHA3_256:
    h = SHA3_256.new()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h

def sign_file(file_path: str, private_key: RSA.RsaKey) -> str:
    h = file_sha3_256(file_path)
    signature = pkcs1_15.new(private_key).sign(h)
    sig_path = file_path + ".sha3-rsa.sig"
    with open(sig_path, "wb") as f:
        f.write(signature)
    return sig_path

def verify_signature(file_path: str, sig_path: str, pubkey_path: str) -> bool:
    h = file_sha3_256(file_path)
    with open(sig_path, "rb") as f:
        signature = f.read()
    with open(pubkey_path, "rb") as f:
        pubkey = RSA.import_key(f.read())
    try:
        pkcs1_15.new(pubkey).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Podpis cyfrowy (RSA + SHA3-256)")
        self.geometry("520x240")
        self.resizable(False, False)

        self.randfunc = None
        self.private_key = None
        self.public_key = None

        title = tk.Label(self, text="RNG w bezpieczeństwie – Podpis cyfrowy", font=("Segoe UI", 14, "bold"))
        title.pack(pady=(16, 8))

        hint = tk.Label(self, text="Wybierz jedną z akcji:", font=("Segoe UI", 10))
        hint.pack(pady=(0, 12))

        btn_frame = tk.Frame(self)
        btn_frame.pack(pady=6)

        sign_btn = tk.Button(btn_frame, text="1) Podpisz plik…", width=24, command=self.on_sign_click)
        sign_btn.grid(row=0, column=0, padx=8, pady=4)

        verify_btn = tk.Button(btn_frame, text='2) Weryfikuj podpis…', width=24, command=self.on_verify_click)
        verify_btn.grid(row=0, column=1, padx=8, pady=4)

        info = (
            "Podpis i klucze są zapisywane w folderze 'keys'."
            "Nazewnictwo kluczy: private_{nazwa_pliku}_key.pem / public_{nazwa_pliku}_key.pem"
        )
        info_lbl = tk.Label(self, text=info, wraplength=480, justify="center")
        info_lbl.pack(padx=16, pady=(12, 0))

    def ensure_rng_and_keys(self):
        if self.randfunc is None:
            seed = load_trng_seed(TRNG_SEED_FILE, SEED_BYTES_MIN)
            self.randfunc = TRNG_DRBG(seed).get_bytes
        if self.private_key is None or self.public_key is None:
            self.private_key, self.public_key = load_or_generate_keys(self.randfunc, RSA_BITS)

    def on_sign_click(self):
        try:
            if self.randfunc is None:
                seed = load_trng_seed(TRNG_SEED_FILE, SEED_BYTES_MIN)
                self.randfunc = TRNG_DRBG(seed).get_bytes

            file_path = filedialog.askopenfilename(
                title="Wybierz plik do podpisania",
                filetypes=[("Wszystkie pliki", "*.*"), ("Dokument tekstowy", ".txt")]
            )
            if not file_path:
                return

            self.private_key, self.public_key, gen_priv, gen_pub = generate_keys_for_file(
                self.randfunc, file_path, RSA_BITS
            )
            pubkey_info = gen_pub

            sig_path = sign_file(file_path, self.private_key)

            messagebox.showinfo(
                "Podpis wykonany",
                f"Podpis zapisano jako:\n{sig_path}\n\n"
                f"Klucz publiczny znajduje się w:\n{pubkey_info}"
            )

        except Exception as e:
            messagebox.showerror("Błąd", str(e))

    def on_verify_click(self):
        try:
            file_path = filedialog.askopenfilename(
                title="Wybierz plik do weryfikacji",
                filetypes=[ ("Dokument tekstowy", ".txt"),("Wszystkie pliki", "*.*")]
            )
            if not file_path:
                return

            sig_path = filedialog.askopenfilename(
                title="Wybierz plik podpisu (.sha3-rsa.sig)",
                filetypes=[("Plik podpisu", "*.sha3-rsa.sig"), ("Wszystkie pliki", "*.*")]
            )
            if not sig_path:
                return

            pubkey_path = filedialog.askopenfilename(
                title="Wybierz publiczny klucz (PEM)",
                filetypes=[("PEM", "*.pem"), ("Wszystkie pliki", "*.*")]
            )
            if not pubkey_path:
                return

            ok = verify_signature(file_path, sig_path, pubkey_path)
            if ok:
                messagebox.showinfo("Weryfikacja", " Podpis poprawny – plik nie był modyfikowany.")
            else:
                messagebox.showwarning("Weryfikacja", " Podpis niepoprawny lub plik został zmieniony.")

        except Exception as e:
            messagebox.showerror("Błąd", str(e))


if __name__ == "__main__":
    App().mainloop()
