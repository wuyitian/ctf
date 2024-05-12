from Crypto.Util.number import getPrime, bytes_to_long
from Crypto.Util.strxor import strxor
from Crypto.PublicKey import RSA

def generate_rsa_params(key_size):
    p = getPrime(key_size)
    q = getPrime(key_size)
    N = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = pow(e, -1, phi)
    return N, e, d

def encrypt(msg, N, e):
    msg = msg.encode()
    msg_length = len(msg)
    key = b'Life is like an ocean only strong-minded can reach the other shore'
    key = key[:msg_length]
    xor_key = strxor(msg, key)
    m = bytes_to_long(xor_key)
    c = pow(m, e, N)
    return c, key, N

N, e, d = generate_rsa_params(512)
ciphertext, key, N = encrypt("This is a secret message", N, e)