import hashlib
import binascii
from pwn import log


# Parameters from gitea.db
salt  = binascii.unhexlify('8bf3e3452b78544f8bee9400d6936d34')  # 16 bytes
key   = 'e531d398946137baea70ed6a680a54385ecff131309c0bd8f225f284406b7cbc8efc5dbef30bf1682619263444ea594cfb56'
dklen = 50
iterations = 50000


def hash(password, salt, iterations, dklen):
    hashValue = hashlib.pbkdf2_hmac(
        hash_name='sha256', 
        password=password, 
        salt=salt, 
        iterations=iterations, 
        dklen=dklen,
        )
    return hashValue


# Crack
dict = '/usr/share/wordlists/rockyou.txt'
bar  = log.progress('Cracking PBKDF2')

with open(dict, 'r', encoding='utf-8') as f:
    for line in f:
        password  = line.strip().encode('utf-8') 
        hashValue = hash(password, salt, iterations, dklen)
        target    = binascii.unhexlify(key)
        # log.info(f'Our target is: {target}')
        bar.status(f'Trying: {password}, hash: {hashValue}')
        if hashValue == target:
            bar.success(f'Found password: {password}!')
            break
        
    bar.failure('Hash is not crackable.')
