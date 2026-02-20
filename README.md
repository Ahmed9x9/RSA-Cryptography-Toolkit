# RSA Cryptography Toolkit

Educational RSA toolkit built with Python and Tkinter for key generation, encryption/decryption, and digital signatures.

## Important Notice

This project is **NOT production-secure crypto**. It is intended for learning and academic demonstration only.

## Features

- RSA key generation with configurable key size
- Text encryption and decryption
- SHA-256 hash-based RSA signing and verification
- Simple desktop GUI using Tkinter

## Requirements

- Python 3.9+
- No external Python packages required

## Run

```bash
python RSA.py
```

## Security Notes

- This implementation uses textbook-style RSA operations for study purposes.
- It does not implement modern production protections such as OAEP/PSS padding.
- Do not use this code to protect real-world sensitive data.

## Repository Contents

- `RSA.py` - Main application source code
- `README.md` - Project overview and usage notes
