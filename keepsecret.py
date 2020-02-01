import sys, getpass, os , stat, crypt
from hmac import compare_digest as check_hash

def build_keeper():


# shadow = 'shadow'

def grep(secrets, key):
    for key,value in secrets:
        if key in secrets:
            print(value)


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

def check_pw_verbose(shadow):
    # We should  check mod of Keepsecret shadow file first
    # it must be 0600
    if check_perm(shadow):
        with open(shadow, 'r') as f:
            data = f.read()
            f.close()
        old_hash = data.rstrip()
        if check_hash(old_hash, crypt.crypt(getpass.getpass('Insert your password to access vault: '), old_hash)):
            return True
        else:
            return False
    else:
        return False

def get_secret(shadow, secrets, key):
    secret_value = None 
    if check_pw_verbose():
        secret_value = grep(secrets, key)
        if value not None:
            return value
    else:
        sys.exit()

def set_secret(shadow, secrets, key, value):
    if check_pw_verbose():
        if secrets.get(key, None) is None:
            secrets[key] = value
        else:
            sys.exit()
        # file system is alredy mounted 
        # is under a folder on the some dir
        print(secrets)


def gen_hash(pw1):
    passwd = crypt.crypt(pw1, crypt.mksalt(crypt.METHOD_SHA512))
    return passwd

def check_pw(shadow, pw0):
    # We should  check mod of Keepsecret shadow file first
    # it must be 0600
    if check_perm(shadow):
        with open(shadow, 'r') as f:
            data = f.read()
            f.close()
        old_hash = data.rstrip()
        if check_hash(old_hash, crypt.crypt(pw0, old_hash)):
            return True
        else:
            return False
    else:
        return False




def insert_pw(shadow, pw1):
    # Your should check mod of Keepsecret shadow file first
    # It must be 0600
    if check_perm(shadow):
        hashed = gen_hash(pw1) 
        with open(shadow, 'w') as f:
            f.write( hashed + '\n')
            f.close()
        return True
    else:
        return False 

def set_pw(shadow):
    count = 0
    while True:
        print('Changing password for Keepsecret: ')
        pw0 = getpass.getpass('(current) Keepsecret password: ')
        if check_pw(shadow ,pw0):
            pw1 = getpass.getpass('Enter new Keepsecret password: ')
            pw2 = getpass.getpass('Retype new Keepsecret password: ')
            if pw1 == pw2:
                if insert_pw(shadow, pw1):
                    print('password updated successfully')
                    break
                else:
                    print('Insert Failed!', file=sys.stderr)
                    break
            else:
                print('Password unchanged', file=sys.stderr)
                count += 1
        else:
            print('Sorry, try again', file=sys.stderr)
            count += 1
        if count >= 2: break 
