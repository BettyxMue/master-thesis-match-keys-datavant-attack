import base64
import secrets

# Generate a 32-byte (256-bit) AES key
site_key = secrets.token_bytes(32)
print(f"Generated AES key (hex): {site_key.hex()}")

# Save the generated key to a text file
with open("generated_key.txt", "w", encoding="utf-8") as key_file:
    key_file.write(f"Generated AES key (hex): {site_key.hex()}\n")
    key_file.write(f"Generated AES key (base64): {base64.b64encode(site_key).decode('utf-8')}\n")
    key_file.write(f"Generated AES key : {site_key}\n")