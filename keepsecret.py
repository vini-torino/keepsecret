#!/usr/bin/python3
# - * - encode: utf-8  - * -
import sys, getpass, os , stat, crypt
from hmac import compare_digest as check_hash
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import base64
import getopt

def check_perm(shadow):
    mode = os.stat(shadow)
    chmod = oct(mode.st_mode)[4:]
    if chmod != '0600':
        print('Permissions '+ chmod +' for' + shadow + ' are too open.')
        print('It is required that the Keepsecret shadow file are NOT accessible by others')
        print('This file will be ignored')
        return False
    return True

def cat_bytes(secret_file):
    with open(secret_file, 'rb') as f:
        data = f.read()
        f.close()
    return data

def write_bytes(secret_file, data):
    with open(secret_file , 'wb' ) as f:
        f.write(data)
        f.close()

def get_key(pw0):
    pw0_bytes = pw0.encode()
    salt = b'keepsecret'
    kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000, 
            backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(pw0_bytes))
    return key

def manage_vault(pw0, secret_file, is_open):
    key = get_key(pw0)
    data = cat_bytes(secret_file)
    fernet_object = Fernet(key)
    if is_open:
        encrypted = fernet_object.encrypt(data)
        write_bytes(secret_file, encrypted)
    else:
        decrypted = fernet_object.decrypt(data)
        write_bytes(secret_file, decrypted)

def manage_secrets(shadow, secret_file, is_open):
    if check_perm(shadow):
        with open(shadow, 'r') as f:
            data = f.read()
            f.close()
        old_hash = data.rstrip()
        pw0 = getpass.getpass('Insert your password to access your secrets: ')
        if check_hash(old_hash, crypt.crypt(pw0, old_hash)):
            manage_vault(pw0, secret_file, is_open)

def new_pw(shadow, secret_file):
    if check_perm(shadow):
        pw1 = getpass.getpass('Insert your password to generate keepsecret vault: ')
        hashed = crypt.crypt(pw1, crypt.mksalt(crypt.METHOD_SHA512))
        encrypt_vault(pw1, secret_file)
        with open(shadow, 'w') as f:
            f.write( hashed + '\n')
            f.close()

shadow = 'shadow'
argv = sys.argv[1:]
try:
    opts, args = getopt.getopt(argv, "n:e:d:", ["new=", "encrypt=", "decrypt"])
except getopt.GetoptError as err:
    print(err)
    opts = []

for opt, arg in opts:
    if opt in ['-n', '--new']:
        new_pw(shadow, arg)
        print(f'setting new password for {arg}')
    elif opt in ['-e', '--encrypt' ]:
        manage_secrets(shadow, arg, True)
        print(f'encrypting {arg}')
    elif opt in ['-d', '--decrypt']:
        manage_secrets(shadow, arg, False)
        print(f'decrypting {arg}')
