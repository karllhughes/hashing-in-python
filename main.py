import bcrypt
import hashlib
import time


def bcrypt_hash_salt(password):
    print("--- Bcrypt Hash + Salt ---")
    start_time = time.time()
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(b"{password}", salt)

    print('Hashed: ' + hashed.decode("utf-8"))
    print("%.15f sec" % (time.time() - start_time))


def sha512_hash(password):
    print("--- Sha512 Hash ---")
    start_time = time.time()
    hashed = hashlib.sha512(b"{password}")

    print('Hashed: ' + hashed.hexdigest())
    print("%.15f sec" % (time.time() - start_time))


def sha512_hash_salt(password):
    print("--- Sha512 Hash + Salt ---")
    start_time = time.time()
    salt = bcrypt.gensalt().decode("utf-8")
    salted_password = password + salt
    hashed = hashlib.sha512(b"{salted_password}")

    print('Hashed: ' + hashed.hexdigest())
    print("%.15f sec" % (time.time() - start_time))


def sha256_hash(password):
    print("--- Sha256 Hash ---")
    start_time = time.time()
    hashed = hashlib.sha256(b"{password}")

    print('Hashed: ' + hashed.hexdigest())
    print("%.15f sec" % (time.time() - start_time))


def sha256_hash_salt(password):
    print("--- Sha256 Hash + Salt ---")
    start_time = time.time()
    salt = bcrypt.gensalt().decode("utf-8")
    salted_password = password + salt
    hashed = hashlib.sha256(b"{salted_password}")

    print('Hashed: ' + hashed.hexdigest())
    print("%.15f sec" % (time.time() - start_time))


def sha1_hash(password):
    print("--- Sha1 Hash ---")
    start_time = time.time()
    hashed = hashlib.sha1(b"{password}")

    print('Hashed: ' + hashed.hexdigest())
    print("%.15f sec" % (time.time() - start_time))


def sha1_hash_salt(password):
    print("--- Sha1 Hash + Salt ---")
    start_time = time.time()
    salt = bcrypt.gensalt().decode("utf-8")
    salted_password = password + salt
    hashed = hashlib.sha1(b"{salted_password}")

    print('Hashed: ' + hashed.hexdigest())
    print("%.15f sec" % (time.time() - start_time))


def md5_hash(password):
    print("--- Sha1 Hash ---")
    start_time = time.time()
    hashed = hashlib.md5(b"{password}")

    print('Hashed: ' + hashed.hexdigest())
    print("%.15f sec" % (time.time() - start_time))


def md5_hash_salt(password):
    print("--- Sha1 Hash + Salt ---")
    start_time = time.time()
    salt = bcrypt.gensalt().decode("utf-8")
    salted_password = password + salt
    hashed = hashlib.md5(b"{salted_password}")

    print('Hashed: ' + hashed.hexdigest())
    print("%.15f sec" % (time.time() - start_time))

if __name__ == '__main__':
    password_to_hash = 'test password'
    bcrypt_hash_salt(password_to_hash)
    sha512_hash(password_to_hash)
    sha512_hash_salt(password_to_hash)
    sha256_hash(password_to_hash)
    sha256_hash_salt(password_to_hash)
    sha1_hash(password_to_hash)
    sha1_hash_salt(password_to_hash)
    md5_hash(password_to_hash)
    md5_hash_salt(password_to_hash)
