
# Author : ALOUACH Abdennour (Student of MIATE 2024/2026)
# Title  : Encryption algorithms (with Python)
# Date   : 14/07/2025

#  Algorithms :
#  -------------------------------------------------
   #  Caesar
   #  Vigenere
   #  Vernam
   #  RSA
   #  Frequency analysis
   #  Diffie-Hellman
   #  ElGamal
   #  Hashing (SHA-256, SHA-512, SHA3-256, SHA3-512)
   #  Digital Signature (RSA)
   #  ECDH
   #  ECDSA
   #  Digital Signature (ECDSA)




#----------  Caesar  ------------------------------------------------------------------------------------------
def caesar_cipher(text, key) :
    txt_ci = ""
    for char in text :
        if char.isalpha() :
            base = ord('A') if char.isupper() else ord('a')
            txt_ci += (chr((ord(char) - base + key) % 26 + base))
        else :
            txt_ci += char
    return txt_ci

def caesar_decipherment(text, key) :
    return caesar_cipher(text, -key)

#text_cesar = "I am a student of MIATE in Nador"
text_cesar = "I am a student of MIATE in Nador, the last is a city in Morocco in region of Oriental"
key_cesar = 3

chiffré = caesar_cipher(text_cesar, key_cesar)
dechiffré = caesar_decipherment(chiffré, key_cesar)

print('----- Caesar ------------------------------------------------------------------------------------------')
print("Encrypted message : ", chiffré)
print("Real message : ", dechiffré)




#----------  Vigenere  ------------------------------------------------------------------------------------------
def vigenere_cipher(text, key, mode='encrypt') :
    result = ""
    index_key = 0
    key_len = len(key)
    for char in text :
        if char.isalpha() :
            base = ord('A') if char.isupper() else ord('a')
            shift = ord(key[index_key % key_len]) - base
            if mode == 'decrypt':
                shift = -shift
            new_char = chr((ord(char) - base + shift) % 26 + base)
            result += new_char
            index_key += 1
        else :
            result += char
    return result

text_vig = "I am a student of MIATE in Nador"
key_vig = "key"

print('\n----- Vigenere ------------------------------------------------------------------------------------------')
print("Encrypted message : ", vigenere_cipher(text_vig, key_vig))
print("Real message : ", vigenere_cipher(vigenere_cipher(text_vig, key_vig), key_vig, 'decrypt'))




#----------  Vernam  ------------------------------------------------------------------------------------------
def vernam_encrypt(message, key):
    """Vernam cipher : XOR character by character"""
    if len(message) != len(key):
        raise ValueError("Message must be the same length with the key") 
    
    result = ''.join(chr(ord(m) ^ ord(k)) for m, k in zip(message, key))
    return result

def vernam_decrypt(ciphertext, key):
    return vernam_encrypt(ciphertext, key)  # same operation as for the encryption

# Example of use
message = "MIATE2025"
key =    "CRYPTOKEY"  # must be random and of the same length as the message

print('\n----- Vernam ------------------------------------------------------------------------------------------')
chiffre = vernam_encrypt(message, key)
print("Encrypted message :", [ord(c) for c in chiffre])  # displayed in numerical values

dechiffre = vernam_decrypt(chiffre, key)
print("Real message :", dechiffre)




#----------  RSA  ------------------------------------------------------------------------------------------
def generate_rsa_keys():
    """ Generate RSA keys """
    # p and q are prime numbers, they are generated randomly by PARI/GP with the command : random(2^512)
    p = 3942491382242225053
    q = 4831086558706002079
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537  # Current value chosen for e
    d = pow(e, -1, phi)
    return (n, e), (n, d)

def rsa_encrypt(message, cle_publique):
    n, e = cle_publique
    return [pow(ord(char), e, n) for char in message]

def rsa_decrypt(message_chiffre, cle_privee):
    n, d = cle_privee
    # Déchiffrement par blocs
    decrypted_blocks = [pow(char, d, n) for char in message_chiffre]
    return ''.join(block.to_bytes((block.bit_length() + 7) // 8, 'big').decode() for block in decrypted_blocks)

# Example of use
message = "I am a student of MIATE in Nador"

print('\n----- RSA ------------------------------------------------------------------------------------------')
cle_publique, cle_privee = generate_rsa_keys()
print("Public key :", cle_publique)
print("Private key :", cle_privee)

# Display the numbers minimized as they are a bit too large, this is done by taking modulo e
message_chiffre = rsa_encrypt(message, cle_publique)
e = 65537
def reduce_mod_e(message_chiffre, e):
    return [val % e for val in message_chiffre]
message_reduit = reduce_mod_e(message_chiffre, e)

#print("Encrypted message :", rsa_encrypt(message, cle_publique))
print("Encrypted message :", message_reduit)
print("Real message :", rsa_decrypt(rsa_encrypt(message, cle_publique), cle_privee))




#----------  Frequency analysis  ------------------------------------------------------------------------------------------
from collections import Counter

def frequency_analysis(texte_chiffre):
    """ Find the secret key using the frequency of letters and the formula e + key ≡ char mod 26 """
    lettres = [char.lower() for char in texte_chiffre if char.isalpha()]
    frequence = Counter(lettres)
    print("Frequency : ",frequence)

    # Find the most frequent letter
    lettre_plus_frequente = max(frequence, key=frequence.get)
    print("Most frequent letter : ", lettre_plus_frequente)

    # Calculate the key assuming that 'e' is the most frequent letter in French
    cle_estimee = (ord(lettre_plus_frequente) - ord('e')) % 26
    return cle_estimee

def caesar_decrypt(texte_chiffre, cle):
    """ Decrypt a Caesar cipher using the estimated key """
    texte_dechiffre = ""
    for char in texte_chiffre:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            texte_dechiffre += chr((ord(char) - base - cle) % 26 + base)
        else:
            texte_dechiffre += char
    return texte_dechiffre

text_cesar_xl = "L dp d vwxghqw ri PLDWH lq Qdgru, wkh odvw lv d flwb lq Prurffr lq uhjlrq ri Rulhqwdo"

print('\n----- Frequency analysis ------------------------------------------------------------------------------------------')
# Example of use
cle_trouvee = frequency_analysis(text_cesar_xl)
message_dechiffre = caesar_decrypt(text_cesar_xl, cle_trouvee)

print(f"Estimated key : {cle_trouvee}")
print(f"Real message : {message_dechiffre}")




#----------  Diffie-Hellman  ------------------------------------------------------------------------------------------
import random

def diffie_hellman():
    """ Implement the Diffie-Hellman key exchange """
    # Prime number
    p = 3942491382242225053
    # Generator, for PARI/GP : lift(znprimroot(p))
    g = 5
    # Choice of private keys
    a = random.randint(2, p - 2)
    b = random.randint(2, p - 2)
    # Calculation of public keys
    A = pow(g, a, p)
    B = pow(g, b, p)
    # exchange of public keys and calculation of the secret key
    cle_secrete_A = pow(B, a, p)
    cle_secrete_B = pow(A, b, p)

    print(f"Prime number (p) : {p}")
    print(f"Generator (g) : {g}")
    print(f"Private key A : {a}, Public key A : {A}")
    print(f"Private key B : {b}, Public key B : {B}")
    print(f"Secret key calculated by A : {cle_secrete_A}")
    print(f"Secret key calculated by B : {cle_secrete_B}")

    if cle_secrete_A != cle_secrete_B : 
        print("Error : the keys do not match !")
    else :
        print("Diffie-Hellman exchange successful !")

print('\n----- Diffie-Hellman ------------------------------------------------------------------------------------------')
# Example of use
diffie_hellman()




#----------  ElGamal  ------------------------------------------------------------------------------------------
import random

def elgamal_key_generation(p, g):
    x = random.randint(1, p-2)  # Private key
    h = pow(g, x, p)  # Public key : h = g^x mod p
    return x, (p, g, h)

def elgamal_encrypt(message, public_key):
    p, g, h = public_key
    k = random.randint(1, p-2)  # Random integer k
    c1 = pow(g, k, p)  # c1 = g^k mod p
    c2 = (message * pow(h, k, p)) % p  # c2 = m * h^k mod p
    return (c1, c2)

def elgamal_decrypt(ciphertext, private_key, p):
    c1, c2 = ciphertext
    s = pow(c1, private_key, p)  # s = c1^x mod p
    s_inv = pow(s, -1, p)  # Inverse of s
    m = (c2 * s_inv) % p  # m = c2 * s^-1 mod p
    return m

# Parameters
p = 3942491382242225053
g = 5  # Generator
message = 647  # Key to exchange (01010000111 in decimal)

print('\n----- ElGamal ------------------------------------------------------------------------------------------')
# Generation of keys
private_key, public_key = elgamal_key_generation(p, g)
print(f"Private key : {private_key}")
print(f"Public key : {public_key}")

# Chiffrement
ciphertext = elgamal_encrypt(message, public_key)
print(f"Encrypted message : {ciphertext}")

# Déchiffrement
decrypted_message = elgamal_decrypt(ciphertext, private_key, p)
print(f"Real message : {decrypted_message}")




#----------  Hashing  ------------------------------------------------------------------------------------------
import hashlib

def hash_sha2_sha3(message):
    """ Calculate the hash with SHA-2 and SHA-3 """
    sha256 = hashlib.sha256(message.encode()).hexdigest()
    sha512 = hashlib.sha512(message.encode()).hexdigest()
    sha3_256 = hashlib.sha3_256(message.encode()).hexdigest()
    sha3_512 = hashlib.sha3_512(message.encode()).hexdigest()

    print(f"SHA-256 : {sha256}")
    print(f"SHA-512 : {sha512}")
    print(f"SHA3-256 : {sha3_256}")
    print(f"SHA3-512 : {sha3_512}")

print('\n----- Hashing ------------------------------------------------------------------------------------------')
# Example of use
message = "Hello, Cryptography! I am a student of MIATE in Nador"
print("Message : ", message)
hash_sha2_sha3(message)




#----------  Digital Signature  ------------------------------------------------------------------------------------------
import hashlib

def sign_message(message, cle_privee):
    n, d = cle_privee
    # Hashing the message
    hash_val = hashlib.sha256(message.encode()).hexdigest()
    hash_int = int(hash_val, 16)
    print(f"Hashing (int) : {hash_int}")  # Display of the hash
    # Reduction of the hash modulo n (necessary because hash_int can be > n)
    hash_int_reduit = hash_int % n
    print(f"Reduced hash (int) : {hash_int_reduit}")  # Display of the reduced hash
    # Signature via modular exponentiation
    signature = pow(hash_int_reduit, d, n)
    return signature

def verifier_signature(message, signature, cle_publique):
    n, e = cle_publique
    # Hashing the message
    hash_recalcule = hashlib.sha256(message.encode()).hexdigest()
    hash_int = int(hash_recalcule, 16)
    print(f"Recalculated hash (int) : {hash_int}")  # Display of the recalculated hash
    # Reduction of the recalculated hash modulo n
    hash_int_reduit = hash_int % n
    print(f"Reduced recalculated hash (int) : {hash_int_reduit}")  # Display of the reduced recalculated hash
    # Decryption of the signature
    signature_dechiffree = pow(signature, e, n)
    print(f"Decrypted signature : {signature_dechiffree}")  # Display of the decrypted signature
    # Comparaison
    return hash_int_reduit == signature_dechiffree

print('\n----- Digital Signature - RSA ------------------------------------------------------------------------------------------')
# Example of use
cle_publique = (5960609, 4873877)
cle_privee = (5960609, 65537)
message = "Cryptographie RSA"
print("Private key : ", cle_privee)
print("Public key : ", cle_publique)

# Signature
signature = sign_message(message, cle_privee)
print(f"Generated signature : {signature}")

# Verification
if verifier_signature(message, signature, cle_publique):
    print("✅ Valid signature : the message is authentic.")
else:
    print("❌ Invalid signature : the message has been altered.")




#----------  ECDH  ------------------------------------------------------------------------------------------
# Parameters of the elliptic curve: y^2 = x^3 + ax + b mod p
a = 2
b = 2
p = 64621  # small prime number for simplicity

# Base point (generator)
G = (5, 1)

# Function to add two points on the curve
def point_add(P, Q):
    if P == Q:
        # Point doubling
        s = ((3 * P[0]**2 + a) * pow(2 * P[1], -1, p)) % p
    else:
        # Regular addition
        s = ((Q[1] - P[1]) * pow(Q[0] - P[0], -1, p)) % p
    x_r = (s**2 - P[0] - Q[0]) % p
    y_r = (s * (P[0] - x_r) - P[1]) % p
    return (x_r, y_r)

# Scalar multiplication: k * G
def scalar_mult(k, P):
    R = P
    for _ in range(k - 1):
        R = point_add(R, P)
    return R

print('\n----- ECDH ------------------------------------------------------------------------------------------')
# Private keys for both users
priv_A = 7
priv_B = 11

# Public keys
pub_A = scalar_mult(priv_A, G)
pub_B = scalar_mult(priv_B, G)

# Shared secret keys
shared_A = scalar_mult(priv_A, pub_B)
shared_B = scalar_mult(priv_B, pub_A)

print(f"Elliptic curve: y² = x³ + {a}x + {b} mod {p}")
print(f"Base point G: {G}")
print("Public key A:", pub_A)
print("Public key B:", pub_B)
print("Shared secret computed by A:", shared_A)
print("Shared secret computed by B:", shared_B)
print("✅ Shared key is identical:", shared_A == shared_B)





#----------  ECDSA  ------------------------------------------------------------------------------------------
# Elliptic curve : y² = x³ + ax + b mod p
a = 2
b = 2
p = 64621  # Small prime number

# Base point (generator)
G = (5, 1)
n = 19  # Order of point G (arbitrarily chosen for the example)

# Point addition function
def point_add(P, Q):
    if P == Q:
        s = ((3 * P[0]**2 + a) * pow(2 * P[1], -1, p)) % p
    else:
        s = ((Q[1] - P[1]) * pow(Q[0] - P[0], -1, p)) % p
    x_r = (s**2 - P[0] - Q[0]) % p
    y_r = (s * (P[0] - x_r) - P[1]) % p
    return (x_r, y_r)

# Scalar multiplication
def scalar_mult(k, P):
    R = P
    for _ in range(k - 1):
        R = point_add(R, P)
    return R

import hashlib
import random

print('\n----- ECDSA ------------------------------------------------------------------------------------------')
# Private and public key
d = 7  # private key
Q = scalar_mult(d, G)  # public key

print(f"Elliptic curve: y² = x³ + {a}x + {b} mod {p}")
print(f"Base point G: {G}")

# Message to sign
message = "Bonjour ECDSA"
e = int(hashlib.sha1(message.encode()).hexdigest(), 16) % n

# Signature (r, s)
while True:
    k = random.randint(1, n - 1)
    R = scalar_mult(k, G)
    r = R[0] % n
    if r == 0:
        continue
    s = (pow(k, -1, n) * (e + d * r)) % n
    if s != 0:
        break

print("🔏 Message signature :", (r, s))

# Verification
w = pow(s, -1, n)
u1 = (e * w) % n
u2 = (r * w) % n
P1 = scalar_mult(u1, G)
P2 = scalar_mult(u2, Q)
V = point_add(P1, P2)
valid = (V[0] % n) == r

print("✅ Valid signature :", valid)

