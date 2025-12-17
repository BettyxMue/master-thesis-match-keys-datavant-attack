#!/usr/bin/env python3
"""
Key Generation Script for AES Encryption
Master Thesis: Record Linkage with Match Key Algorithms - Is it secure?
Author: Babett Müller

This script generates a random 16-byte (128-bit) AES key suitable for encrypting match key tokens.
The generated key is printed in hexadecimal format and saved to a text file named "generated_key.txt".

Usage:
    python3 scripts/gen_key.py
"""

import base64
import secrets

# Generate a 16-byte (128-bit) AES key
site_key = secrets.token_bytes(16)
print(f"Generated AES key (hex): {site_key.hex()}")

# Save the generated key to a text file
with open("generated_key.txt", "w", encoding="utf-8") as key_file:
    key_file.write(f"Generated AES key (hex): {site_key.hex()}\n")
    key_file.write(f"Generated AES key (base64): {base64.b64encode(site_key).decode('utf-8')}\n")
    key_file.write(f"Generated AES key : {site_key}\n")