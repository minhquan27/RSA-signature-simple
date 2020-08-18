import random
from hashlib import sha256, sha384, sha512
import sympy
import random
import math as mt


def gcd(a, b):
    # Find the greatest common divisor of two numbers
    while b != 0:
        a, b = b, a % b
    return a


def return_coprime_number(phi):
    e = random.randrange(1, phi)
    g = gcd(e, phi)
    while g != 1:
        e = random.randrange(1, phi)
        g = gcd(e, phi)
    return e


def extended_gcd(aa, bb):
    lastremainder, remainder = abs(aa), abs(bb)
    x, lastx, y, lasty = 0, 1, 1, 0
    while remainder:
        lastremainder, (quotient, remainder) = remainder, divmod(lastremainder, remainder)
        x, lastx = lastx - quotient * x, x
        y, lasty = lasty - quotient * y, y
    return lastremainder, lastx * (-1 if aa < 0 else 1), lasty * (-1 if bb < 0 else 1)


# Euclid's extended algorithm for finding the multiplicative inverse of two numbers
def modinv(a, m):
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise Exception('Modular inverse does not exist')
    return x % m


def random_prime_number(a, b):
    # return to numbers prime in range (a,b), compute n and phi
    number_prime1 = sympy.randprime(a, b)
    number_prime2 = sympy.randprime(a, b)

    return number_prime1, number_prime2


def generate_key(number_prime1, number_prime2):
    n = number_prime1 * number_prime2
    phi = (number_prime1 - 1) * (number_prime2 - 1)
    e = return_coprime_number(phi)
    d = modinv(e, phi)
    # public_key = n,e
    # private_key = number_prime1, number_prime2 ,d
    return (n, e), (number_prime1, number_prime2, d)


def encrypt(public_key, plaintext):
    n, e = public_key
    cipher_text = (plaintext ** e) % n
    return cipher_text


def decrypt(private_key, cipher_text):
    p, q, d = private_key
    plain_text = (cipher_text ** d) % (p * q)
    return plain_text


def encrypt_signature(private_key, plaintext):
    p, q, d = private_key
    n = p * q
    # covert plaintext to number
    number_repr = [ord(char) for char in plaintext]
    print("number representation before encryption:", number_repr)
    cipher = [pow(ord(char), d, n) for char in plaintext]
    return cipher


def decrypt_signature(public_key, ciphertext):
    n, e = public_key
    # ciphertext to plaintext number
    number_repr = [pow(char, e, n) for char in ciphertext]
    print("decryted number representation is:", number_repr)
    # cover plaintext to number
    plain = [chr(pow(char, e, n)) for char in ciphertext]
    # return the array of bytes as a string
    return ''.join(plain)


def hash_function(message, hash_type):
    if hash_type == 'sha256':
        hashed = sha256(message.encode('UTF-8')).hexdigest()
    elif hash_type == 'sha384':
        hashed = sha384(message.encode('UTF-8')).hexdigest()
    elif hash_type == 'sha512':
        hashed = sha512(message.encode('UTF-8')).hexdigest()

    return hashed


def verify(received_hashed, message, hash_type):
    our_hashed = hash_function(message, hash_type)
    if received_hashed == our_hashed:
        print("Verification successful!")
        print(received_hashed, "=", our_hashed)
    else:
        print("Warning!! signature could not be verified")
        print(received_hashed, "not", our_hashed)


if __name__ == '__main__':
    '''number1_prime, number2_prime = random_prime_number(1000, 5000)
    print(number1_prime)
    print(number2_prime)
    public_key, private_key = generate_key(number1_prime, number2_prime)
    plaint_text = 3213
    cipher_text = encrypt(public_key, plaint_text)
    print("cipher_text:", cipher_text)
    plaint_text = decrypt(private_key, cipher_text)
    print("plaint_text:", plaint_text)
    '''
    number1_prime, number2_prime = random_prime_number(2**1024, 2**2048)
    print("number1_prime:", number1_prime)
    print("number2_prime:", number2_prime)
    print("---------------------------------------------")
    public_key, private_key = generate_key(number1_prime, number2_prime)
    string_message = 'Vien Toan Ung Dung va Tin Hoc Dai Hoc Bach Khoa Ha Noi'
    string_message_1 = 'Vien Toan Ung Dung va Tin Hoc Dai Hoc Bach Khoa Ha Noi a'
    h = hash_function(string_message, 'sha256')
    print("hash_message:\n", h)
    print("---------------------------------------------")
    a = encrypt_signature(private_key, h)
    print(a)
    print("---------------------------------------------")
    b = decrypt_signature(public_key, a)
    print(b)
    print("----------------------------------------------")
    verify(b, string_message, 'sha256')

    '''number1_prime, number2_prime = random_prime_number(100000, 500000)
    print(number1_prime)
    '''
