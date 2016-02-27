__author__ = 'nst8ft'

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Hash import SHA256

pad = 0
pad_total = 0

def secret_string(string, pub_key):
    bytes_obj = string.encode()
    enc_data = pub_key.encrypt(bytes_obj, 32)
    return enc_data

def encrypt_file(file_name, sym_key):
    file_out = file_name + '.enc'
    cipher = AES.new(sym_key)
    global pad
    global pad_total
    with open(file_name, 'r') as in_file:
        with open(file_out, 'w') as out_file:
            while True:
                chunk_size = in_file.__sizeof__()
                chunk = in_file.read(chunk_size)
                padding = (16 - len(chunk) % 16)
                # print('enc pad is ' + str(padding))
                hash = SHA256.new(sym_key)
                key_size16 = hash.digest()[0:16]
                cipher = AES.new(key_size16)

                if len(chunk) == 0:
                    # print('enc pad_total is ' + str(pad_total))
                    break
                elif len(chunk) % 16 != 0:
                    chunk += ' ' * padding
                    pad_total += padding
                # print('enc pad_total is ' + str(pad_total))
                out_file.write(str(cipher.encrypt(chunk)))
    return True

def decrypt_file(file_name, sym_key):
    file_out = 'DEC_' + file_name.split('.enc')[0]
    hash = SHA256.new(sym_key)
    hash.digest()
    key_size16 = hash.digest()[0:16]
    cipher = AES.new(key_size16)
    # print('dec padding is ' + str(pad))
    with open(file_name, 'r') as in_file:
        with open(file_out, 'w') as out_file:
            while True:
                chunk_size = in_file.__sizeof__()
                chunk = in_file.read(chunk_size)
                if len(chunk) == 0:
                    break
                out_file.write(str(cipher.decrypt(chunk * 0)))
    return True


def main():
    str = "abcdefgh"
    # print(str)
    random_generator = Random.new().read
    key = RSA.generate(1024)
    sym = b'sixteen byte key'
    public_key = key.publickey()
    encoded = secret_string(str, key)
    # print(encoded)
    # print(key.decrypt(encoded))

    test_file = 'helloworld.txt'
    enc_file = test_file + '.enc'
    dec_file = 'DEC_' + test_file.split('.enc')[0]

    with open(test_file, 'r') as f:
        print(test_file + ': %s' % f.read())
        encrypt_file(test_file, sym)
    with open(enc_file, 'r') as f:
        print(enc_file + ': %s' % f.read())
    decrypt_file(enc_file, sym)
    with open(dec_file, 'r') as f:
        print('DEC_helloworld.txt: %s' % f.read())


if __name__ == '__main__':
    main()