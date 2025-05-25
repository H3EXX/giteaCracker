import hashlib
import binascii
import sys
from pwn import log

# Validate command line arguments
if len(sys.argv) != 3:
    print(f"Usage: {sys.argv[0]} <salt_in_hex> <key_in_hex>")
    sys.exit(1)

# Read arguments
try:
    salt = binascii.unhexlify(sys.argv[1])
    key = binascii.unhexlify(sys.argv[2])
except binascii.Error:
    print("Invalid hex string for salt or key.")
    sys.exit(1)

# Fixed parameters
dklen = 50
iterations = 50000

def hash_password(password, salt, iterations, dklen):
    return hashlib.pbkdf2_hmac(
        hash_name='sha256', 
        password=password, 
        salt=salt, 
        iterations=iterations, 
        dklen=dklen
    )

# Crack password using dictionary
dict_path = '/usr/share/wordlists/rockyou.txt'
bar = log.progress('Cracking PBKDF2')

with open(dict_path, 'r', encoding='utf-8') as f:
    for line in f:
        password = line.strip().encode('utf-8')
        hash_val = hash_password(password, salt, iterations, dklen)
        bar.status(f'Trying: {password.decode("utf-8", errors="ignore")}')
        if hash_val == key:
            bar.success(f'Found password: {password.decode("utf-8", errors="ignore")}')
            break
    else:
        bar.failure('Hash is not crackable.')
