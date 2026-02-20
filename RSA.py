import math
import secrets
from hashlib import sha256
import tkinter as tk
from tkinter import messagebox

def is_prime(n, rounds=None):
    if n in (2, 3):
        return True
    if n < 2 or n % 2 == 0:
        return False

    small_primes = (3, 5, 7, 11, 13, 17, 19, 23, 29, 31)
    for p in small_primes:
        if n == p:
            return True
        if n % p == 0:
            return False

    if rounds is None:
        rounds = max(10, min(40, n.bit_length() // 32 + 8))

    # write n-1 as d * 2^s
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

# Generate a random prime with exact bit length
def generate_prime(bits=256):
    if bits < 8:
        raise ValueError("Prime bit size must be at least 8")

    while True:
        p = secrets.randbits(bits)
        p |= (1 << (bits - 1)) | 1
        if is_prime(p):
            return p

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    g, x1, y1 = egcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return (g, x, y)

def modinv(a, m):
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError("modular inverse does not exist")
    return x % m


def max_message_chunk_bytes(n):
    k = (n.bit_length() - 1) // 8
    if k < 2:
        raise ValueError("RSA modulus is too small for block operations")
    return k - 1


# Generate p, q, n, e, d
def generate_keys(bits=512):
    if bits < 32:
        raise ValueError("Key size must be at least 32 bits")

    p_bits = bits // 2
    q_bits = bits - p_bits
    p = generate_prime(p_bits)
    q = generate_prime(q_bits)
    while q == p:
        q = generate_prime(q_bits)

    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537

    if math.gcd(e, phi) != 1:
        e = 3
        while math.gcd(e, phi) != 1:
            e += 2

    d = modinv(e, phi)
    return p, q, n, e, d


# Encrypt
def chunk_encrypt(text, e, n):
    chunk_size = max_message_chunk_bytes(n)
    text_bytes = text.encode("utf-8")
    payload = len(text_bytes).to_bytes(4, "big") + text_bytes

    blocks = []
    for i in range(0, len(payload), chunk_size):
        block = payload[i : i + chunk_size]
        if len(block) < chunk_size:
            block = block.ljust(chunk_size, b"\x00")
        blocks.append(int.from_bytes(block, "big"))

    cipher_ints = [str(pow(b, e, n)) for b in blocks]
    return ",".join(cipher_ints)


# Decrypt
def chunk_decrypt(ciphertext, d, n):
    chunk_size = max_message_chunk_bytes(n)
    plaintext = bytearray()
    blocks = [blk.strip() for blk in ciphertext.split(",") if blk.strip()]

    if not blocks:
        return ""

    for blk in blocks:
        c = int(blk)
        if c < 0 or c >= n:
            raise ValueError("Cipher block out of range")

        m = pow(c, d, n)
        block = m.to_bytes(chunk_size, "big")
        plaintext.extend(block)

    if len(plaintext) < 4:
        raise ValueError("Ciphertext is too short or corrupted")

    msg_len = int.from_bytes(plaintext[:4], "big")
    available = len(plaintext) - 4
    if msg_len > available:
        raise ValueError("Ciphertext payload length is invalid")

    msg = bytes(plaintext[4 : 4 + msg_len])
    try:
        return msg.decode("utf-8")
    except UnicodeDecodeError as ex:
        raise ValueError("Decrypted data is not valid UTF-8 text") from ex


# SHA-256 then RSA-sign (textbook, for study)
def sign(message, d, n):
    h = int.from_bytes(sha256(message.encode("utf-8")).digest(), byteorder="big") % n
    return pow(h, d, n)


# Verify RSA signature
def verify(message, signature, e, n):
    h = int.from_bytes(sha256(message.encode("utf-8")).digest(), byteorder="big") % n
    return pow(signature, e, n) == h


class RSAApp:
    def __init__(self, master):
        master.title("RSA Cryptography App")

        self.n = self.e = self.d = None

        # Key Generation
        fk = tk.LabelFrame(master, text="Key Generation")
        fk.pack(fill="x", padx=10, pady=5)

        bits_row = tk.Frame(fk)
        bits_row.pack(fill="x", padx=5, pady=3)
        tk.Label(bits_row, text="Key size (bits):").pack(side="left")
        self.ent_bits = tk.Entry(bits_row, width=10)
        self.ent_bits.insert(0, "512")
        self.ent_bits.pack(side="left", padx=6)

        tk.Button(fk, text="Generate Keys", command=self.on_generate).pack(pady=5)
        self.txt_keys = tk.Text(fk, height=6, width=80)
        self.txt_keys.pack(padx=5, pady=(0, 5))

        # Encryption/Decryption
        fe = tk.LabelFrame(master, text="Encrypt / Decrypt")
        fe.pack(fill="x", padx=10, pady=5)

        tk.Label(fe, text="Plaintext:").pack(anchor="w")
        self.ent_plain = tk.Entry(fe, width=80)
        self.ent_plain.pack(padx=5)

        tk.Button(fe, text="Encrypt", command=self.on_encrypt).pack(pady=2)
        tk.Label(fe, text="Ciphertext (comma-separated blocks):").pack(anchor="w")
        self.ent_cipher = tk.Entry(fe, width=80)
        self.ent_cipher.pack(padx=5)

        tk.Button(fe, text="Decrypt", command=self.on_decrypt).pack(pady=2)
        tk.Label(fe, text="Decrypted:").pack(anchor="w")
        self.ent_decrypt = tk.Entry(fe, width=80)
        self.ent_decrypt.pack(padx=5)

        # Digital Signature
        fs = tk.LabelFrame(master, text="Digital Signature")
        fs.pack(fill="x", padx=10, pady=5)

        tk.Label(fs, text="Message:").pack(anchor="w")
        self.ent_msg = tk.Entry(fs, width=80)
        self.ent_msg.pack(padx=5)
        tk.Button(fs, text="Sign", command=self.on_sign).pack(pady=2)

        tk.Label(fs, text="Signature:").pack(anchor="w")
        self.ent_sig = tk.Entry(fs, width=80)
        self.ent_sig.pack(padx=5)
        tk.Button(fs, text="Verify", command=self.on_verify).pack(pady=2)
        self.lbl_result = tk.Label(fs, text="")
        self.lbl_result.pack(pady=(0, 4))

    def _have_keys(self):
        return self.n is not None and self.e is not None and self.d is not None

    def on_generate(self):
        try:
            bits = int(self.ent_bits.get().strip())
            if bits < 32:
                raise ValueError("Bit size must be at least 32")
            if bits % 2 != 0:
                raise ValueError("Use an even bit size (e.g., 256, 512, 1024)")

            p, q, n, e, d = generate_keys(bits=bits)
            self.p, self.q, self.n, self.e, self.d = p, q, n, e, d

            self.txt_keys.delete("1.0", tk.END)
            self.txt_keys.insert(
                tk.END,
                f"p = {p}\n"
                f"q = {q}\n"
                f"n = {n}\n"
                f"e = {e}\n"
                f"d = {d}\n"
                f"modulus bits = {n.bit_length()}\n"
                f"max plaintext bytes/block = {max_message_chunk_bytes(n)}\n",
            )
            self.lbl_result.config(text="", fg="black")
        except Exception as ex:
            messagebox.showerror("Key generation error", str(ex))

    def on_encrypt(self):
        if not self._have_keys():
            messagebox.showerror("Error", "Generate keys first")
            return
        try:
            plaintext = self.ent_plain.get()
            ctext = chunk_encrypt(plaintext, self.e, self.n)
            self.ent_cipher.delete(0, tk.END)
            self.ent_cipher.insert(0, ctext)
            self.lbl_result.config(text="Encrypted successfully", fg="blue")
        except Exception as ex:
            messagebox.showerror("Encrypt error", str(ex))

    def on_decrypt(self):
        if not self._have_keys():
            messagebox.showerror("Error", "Generate keys first")
            return
        try:
            pt = chunk_decrypt(self.ent_cipher.get(), self.d, self.n)
            self.ent_decrypt.delete(0, tk.END)
            self.ent_decrypt.insert(0, pt)
            self.lbl_result.config(text="Decrypted successfully", fg="blue")
        except Exception as ex:
            messagebox.showerror("Decrypt error", str(ex))

    def on_sign(self):
        if not self._have_keys():
            messagebox.showerror("Error", "Generate keys first")
            return
        try:
            msg = self.ent_msg.get()
            sig = sign(msg, self.d, self.n)
            self.ent_sig.delete(0, tk.END)
            self.ent_sig.insert(0, str(sig))
            self.lbl_result.config(text="Message signed", fg="blue")
        except Exception as ex:
            messagebox.showerror("Sign error", str(ex))

    def on_verify(self):
        if not self._have_keys():
            messagebox.showerror("Error", "Generate keys first")
            return
        try:
            sig_text = self.ent_sig.get().strip()
            if not sig_text:
                raise ValueError("Signature field is empty")

            signature = int(sig_text)
            valid = verify(self.ent_msg.get(), signature, self.e, self.n)
            self.lbl_result.config(
                text="Valid" if valid else "Invalid",
                fg="green" if valid else "red",
            )
        except Exception as ex:
            messagebox.showerror("Verify error", str(ex))


if __name__ == "__main__":
    root = tk.Tk()
    RSAApp(root)
    root.mainloop()





