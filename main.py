import bcrypt
import hashlib
import secrets
import time


def md5_hash(password):
    print("--- MD5 Hash ---")
    start_time = time.time()
    hashed = hashlib.md5(bytes(password, 'utf-8'))

    print('Hashed: ' + hashed.hexdigest())
    print("%.15f ms" % ((time.time() - start_time)*1000))


def md5_hash_salt(password):
    print("--- MD5 Hash + Salt ---")
    start_time = time.time()
    salt = secrets.token_hex(16)
    salted_password = password + salt
    hashed = hashlib.md5(bytes(salted_password, 'utf-8'))

    print('Hashed: ' + hashed.hexdigest())
    print("%.15f ms" % ((time.time() - start_time)*1000))


def sha1_hash(password):
    print("--- Sha1 Hash ---")
    start_time = time.time()
    hashed = hashlib.sha1(bytes(password, 'utf-8'))

    print('Hashed: ' + hashed.hexdigest())
    print("%.15f ms" % ((time.time() - start_time)*1000))


def sha1_hash_salt(password):
    print("--- Sha1 Hash + Salt ---")
    start_time = time.time()
    salt = secrets.token_hex(16)
    salted_password = password + salt
    hashed = hashlib.sha1(bytes(salted_password, 'utf-8'))

    print('Hashed: ' + hashed.hexdigest())
    print("%.15f ms" % ((time.time() - start_time)*1000))


def sha256_hash(password):
    print("--- Sha256 Hash ---")
    start_time = time.time()
    hashed = hashlib.sha256(bytes(password, 'utf-8'))

    print('Hashed: ' + hashed.hexdigest())
    print("%.15f ms" % ((time.time() - start_time)*1000))


def sha256_hash_salt(password):
    print("--- Sha256 Hash + Salt ---")
    start_time = time.time()
    salt = secrets.token_hex(16)
    salted_password = password + salt
    hashed = hashlib.sha256(bytes(salted_password, 'utf-8'))

    print('Hashed: ' + hashed.hexdigest())
    print("%.15f ms" % ((time.time() - start_time)*1000))


def sha512_hash(password):
    print("--- Sha512 Hash ---")
    start_time = time.time()
    hashed = hashlib.sha512(bytes(password, 'utf-8'))

    print('Hashed: ' + hashed.hexdigest())
    print("%.15f ms" % ((time.time() - start_time)*1000))


def sha512_hash_salt(password):
    print("--- Sha512 Hash + Salt ---")
    start_time = time.time()
    salt = secrets.token_hex(16)
    salted_password = password + salt
    hashed = hashlib.sha512(bytes(salted_password, 'utf-8'))

    print('Hashed: ' + hashed.hexdigest())
    print("%.15f ms" % ((time.time() - start_time)*1000))


def bcrypt_hash_salt(password):
    print("--- Bcrypt Hash + Salt ---")
    start_time = time.time()
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(bytes(password, 'utf-8'), salt)

    print('Hashed: ' + hashed.decode("utf-8"))
    print("%.15f ms" % ((time.time() - start_time)*1000))

if __name__ == '__main__':
    password_to_hash = 'test password'
    md5_hash(password_to_hash)
    md5_hash_salt(password_to_hash)
    sha1_hash(password_to_hash)
    sha1_hash_salt(password_to_hash)
    sha256_hash(password_to_hash)
    sha256_hash_salt(password_to_hash)
    sha512_hash(password_to_hash)
    sha512_hash_salt(password_to_hash)
    bcrypt_hash_salt(password_to_hash)
