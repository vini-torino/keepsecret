import sys, getpass, os , stat, crypt
from hmac import compare_digest as check_hash
from time import sleep 
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import base64

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

def open_vault(pw0, secret_file, is_plain):
    key = get_key(pw0)
    data = cat_bytes(secret_file)
    fernet_object = Fernet(key)
    if is_plain:
        encrypted = fernet_object.encrypt(data)
        write_bytes(secret_file, encrypted)
    else:
        decrypted = fernet_object.decrypt(data)
        write_bytes(secret_file, decrypted)

def encrypt_vault(pw0, secret_file):
    open_vault(pw0, secret_file, True)

def decrypt_vault(pw0, secret_file):
    open_vault(pw0, secret_file, False)


def check_perm(shadow):
    mode = os.stat(shadow)
    chmod = oct(mode.st_mode)[4:]
    if chmod != '0600':
        print('Permissions '+ chmod +' for' + shadow + ' are too open.')
        print('It is required that the Keepsecret shadow file are NOT accessible by others')
        print('This file will be ignored')
        return False
    else:
        return True

def open_secrets(shadow, secret_file):
    # We should  check mod of Keepsecret shadow file first
    # it must be 0600
    if check_perm(shadow):
        with open(shadow, 'r') as f:
            data = f.read()
            f.close()
        old_hash = data.rstrip()
        pw0 = getpass.getpass('Insert your password to access the  vault: ')
        if check_hash(old_hash, crypt.crypt(pw0, old_hash)):
            decrypt_vault(pw0, secret_file)
            return True
        else:
            return False
    else:
        return False

def close_secrets(shadow, secret_file):
    # We should  check mod of Keepsecret shadow file first
    # it must be 0600
    if check_perm(shadow):
        with open(shadow, 'r') as f:
            data = f.read()
            f.close()
        old_hash = data.rstrip()
        pw0 = getpass.getpass('Insert your password to hide your secrets: ')
        if check_hash(old_hash, crypt.crypt(pw0, old_hash)):
            encrypt_vault(pw0, secret_file)
            return True
        else:
            return False
    else:
        return False

def gen_hash(pw1):
    passwd = crypt.crypt(pw1, crypt.mksalt(crypt.METHOD_SHA512))
    return passwd

def check_pw(shadow, pw0, secret_file):
    # We should  check mod of Keepsecret shadow file first
    # it must be 0600
    if check_perm(shadow):
        with open(shadow, 'r') as f:
            data = f.read()
            f.close()
        old_hash = data.rstrip()
        if check_hash(old_hash, crypt.crypt(pw0, old_hash)):
            decrypt_vault(pw0, secret_file)
            return True
        else:
            return False
    else:
        return False

def insert_pw(shadow, pw1, secret_file):
    # Your should check mod of Keepsecret shadow file first
    # It must be 0600
    if check_perm(shadow):
        hashed = gen_hash(pw1)
        encrypt_vault(pw1, secret_file)
        with open(shadow, 'w') as f:
            f.write( hashed + '\n')
            f.close()
        return True
    else:
        return False 

def new_pw(shadow, secret_file):
    # Your should check mod of Keepsecret shadow file first
    # It must be 0600
    if check_perm(shadow):
        pw1 = getpass.getpass('Insert your password to generate keepsecret vault: ')
        hashed = crypt.crypt(pw1, crypt.mksalt(crypt.METHOD_SHA512))
        encrypt_vault(pw1, secret_file)
        with open(shadow, 'w') as f:
            f.write( hashed + '\n')
            f.close()


def set_pw(shadow, secret_file):
        for i in range(3):
            print('Changing password for Keepsecret: ')
            pw0 = getpass.getpass('(current) Keepsecret password: ')
            if check_pw(shadow ,pw0, secret_file):
                pw1 = getpass.getpass('Enter new Keepsecret password: ')
                pw2 = getpass.getpass('Retype new Keepsecret password: ')
                if pw1 == pw2:
                    if insert_pw(shadow, pw1, secret_file):
                        print('password updated successfully')
                        break
                    else:
                        print('Insert Failed!', file=sys.stderr)
                        break
                else:
                    print('Password unchanged', file=sys.stderr)
        else:
            print('Sorry, try again', file=sys.stderr)
        sleep(2)

