#####################################################
# GA17 Privacy Enhancing Technologies -- Lab 01
#
# Basics of Petlib, encryption, signatures and
# an end-to-end encryption system.
#
# Run the tests through:
# $ py.test-2.7 -v Lab01Tests.py 

###########################
# Group Members: TODO
###########################


#####################################################
# TASK 1 -- Ensure petlib is installed on the System
#           and also pytest. Ensure the Lab Code can 
#           be imported.

import petlib

#####################################################
# TASK 2 -- Symmetric encryption using AES-GCM 
#           (Galois Counter Mode)
#
# Implement a encryption and decryption function
# that simply performs AES_GCM symmetric encryption
# and decryption using the functions in petlib.cipher.

from os import urandom
from petlib.cipher import Cipher

def encrypt_message(K, message):
    """ Encrypt a message under a key K """

    plaintext = message.encode("utf8")
    
    ## YOUR CODE HERE
    aes = Cipher("aes-128-gcm")
    iv = urandom(16)

    ciphertext, tag = aes.quick_gcm_enc(K, iv, plaintext)

    return (iv, ciphertext, tag)

def decrypt_message(K, iv, ciphertext, tag):
    """ Decrypt a cipher text under a key K 

        In case the decryption fails, throw an exception.
    """
    ## YOUR CODE HERE
    aes = Cipher("aes-128-gcm")

    try:
        plain = aes.quick_gcm_dec(K, iv, ciphertext, tag)
    except:
       raise Exception("decryption failed")

    return plain.encode("utf8")

#####################################################
# TASK 3 -- Understand Elliptic Curve Arithmetic
#           - Test if a point is on a curve.
#           - Implement Point addition.
#           - Implement Point doubling.
#           - Implement Scalar multiplication (double & add).
#           - Implement Scalar multiplication (Montgomery ladder).
#
# MUST NOT USE ANY OF THE petlib.ec FUNCIONS. Only petlib.bn!

from petlib.bn import Bn


def is_point_on_curve(a, b, p, x, y):
    """
    Check that a point (x, y) is on the curve defined by a,b and prime p.
    Reminder: an Elliptic Curve on a prime field p is defined as:

              y^2 = x^3 + ax + b (mod p)
                  (Weierstrass form)

    Return True if point (x,y) is on curve, otherwise False.
    By convention a (None, None) point represents "infinity".
    """
    assert isinstance(a, Bn)
    assert isinstance(b, Bn)
    assert isinstance(p, Bn) and p > 0
    assert (isinstance(x, Bn) and isinstance(y, Bn)) \
           or (x is None and y is None)

    if x is None and y is None:
        return True

    lhs = (y * y) % p
    rhs = (x*x*x + a*x + b) % p
    on_curve = (lhs == rhs)

    return on_curve


def point_add(a, b, p, x0, y0, x1, y1):
    """Define the "addition" operation for 2 EC Points.

    Reminder: (xr, yr) = (xq, yq) + (xp, yp)
    is defined as:
        lam = (yq - yp) * (xq - xp)^-1 (mod p)
        xr  = lam^2 - xp - xq (mod p)
        yr  = lam * (xp - xr) - yp (mod p)

    Return the point resulting from the addition. Raises an Exception if the points are equal.
    """

    # ADD YOUR CODE BELOW
    # lam = ((y1 - y0) * (x1 - x0)^-1)%p
    # xr  = (lam^2 - xp - xq) %p
    # yr  = (lam * (xp - xr) - yp ) %p
    # xr, yr = None, None

    if (str(x0) == str(x1)) and (str(y0) == str(y1)):
        raise Exception("EC Points must not be equal")

    # Check for inverse
    if ( (str(x0) == str(x1)) or (not is_point_on_curve(a, b, p, x0, y0)) or (not is_point_on_curve(a, b, p, x1, y1))):
        return (None, None)

    # Check whether either point is infinity
    if (x0 is None and y0 is None):
        return (x1, y1)

    if (x1 is None and y1 is None):
        return (x0, y0)

    lam = (y1.mod_sub(y0, p)).mod_mul((x1.mod_sub(x0, p).mod_inverse(p)), p)
    xr = lam.mod_pow(2, p).mod_sub(x0, p).mod_sub(x1, p)
    yr = x0.mod_sub(xr, p).mod_mul(lam, p).mod_sub(y0, p)
    
    return (xr, yr)

def point_double(a, b, p, x, y):
    """Define "doubling" an EC point.
     A special case, when a point needs to be added to itself.

     Reminder:
        lam = (3 * xp ^ 2 + a) * (2 * yp) ^ -1 (mod p)
        xr  = lam ^ 2 - 2 * xp
        yr  = lam * (xp - xr) - yp (mod p)

    Returns the point representing the double of the input (x, y).
    """  

    # ADD YOUR CODE BELOW
    if x is None and y is None:
        return None, None

    xr, yr = None, None

    lam = (x.mod_pow(2, p).mod_mul(Bn(3), p).mod_add(a, p)).mod_mul((Bn(2).mod_mul(y, p).mod_inverse(p)), p)
    xr = lam.mod_pow(2, p).mod_sub(Bn(2).mod_mul(x, p), p)
    yr = x.mod_sub(xr, p).mod_mul(lam, p).mod_sub(y, p)

    return xr, yr

def point_scalar_multiplication_double_and_add(a, b, p, x, y, scalar):
    """
    Implement Point multiplication with a scalar:
        r * (x, y) = (x, y) + ... + (x, y)    (r times)

    Reminder of Double and Multiply algorithm: r * P
        Q = infinity
        for i = 0 to num_bits(P)-1
            if bit i of r == 1 then
                Q = Q + P
            P = 2 * P
        return Q

    """
    Q = (None, None)
    P = (x, y)

    for i in range(scalar.num_bits()):
        if scalar.is_bit_set(i):
            Q = point_add(a, b, p, Q[0], Q[1], P[0], P[1])
        P = point_double(a, b, p, P[0], P[1])

    return Q

def point_scalar_multiplication_montgomerry_ladder(a, b, p, x, y, scalar):
    """
    Implement Point multiplication with a scalar:
        r * (x, y) = (x, y) + ... + (x, y)    (r times)

    Reminder of Double and Multiply algorithm: r * P
        R0 = infinity
        R1 = P
        for i in num_bits(P)-1 to zero:
            if di = 0:
                R1 = R0 + R1
                R0 = 2R0
            else
                R0 = R0 + R1
                R1 = 2 R1
        return R0

    """
    R0 = (None, None)
    R1 = (x, y)

    for i in reversed(range(0,scalar.num_bits())):
        ## ADD YOUR CODE HERE
        if scalar.is_bit_set(i):
            R0 = point_add(a, b, p, R0[0], R0[1], R1[0], R1[1])
            R1 = point_double(a, b, p, R1[0], R1[1])
        else:
            R1 = point_add(a, b, p, R0[0], R0[1], R1[0], R1[1])
            R0 = point_double(a, b, p, R0[0], R0[1])

    return R0


#####################################################
# TASK 4 -- Standard ECDSA signatures
#
#          - Implement a key / param generation 
#          - Implement ECDSA signature using petlib.ecdsa
#          - Implement ECDSA signature verification 
#            using petlib.ecdsa

from hashlib import md5, sha256
from petlib.ec import EcGroup
from petlib.ecdsa import do_ecdsa_setup, do_ecdsa_sign, do_ecdsa_verify

def ecdsa_key_gen():
    """ Returns an EC group, a random private key for signing 
        and the corresponding public key for verification"""
    G = EcGroup()
    priv_sign = G.order().random()
    pub_verify = priv_sign * G.generator()
    return (G, priv_sign, pub_verify)


def ecdsa_sign(G, priv_sign, message):
    """ Sign the SHA256 digest of the message using ECDSA and return a signature """
    plaintext =  message.encode("utf8")

    ## YOUR CODE HERE
    G = EcGroup()
    ver_key = priv_sign * G.generator()
    digest = sha256(plaintext).digest()
    kinv_rp = do_ecdsa_setup(G, priv_sign)
    sig = do_ecdsa_sign(G, priv_sign, digest, kinv_rp = kinv_rp)

    return sig

def ecdsa_verify(G, pub_verify, message, sig):
    """ Verify the ECDSA signature on the message """
    plaintext =  message.encode("utf8")

    ## YOUR CODE HERE
    digest = sha256(plaintext).digest()
    res = do_ecdsa_verify(G, pub_verify, sig, digest)

    return res

#####################################################
# TASK 5 -- Diffie-Hellman Key Exchange and Derivation
#           - use Bob's public key to derive a shared key.
#           - Use Bob's public key to encrypt a message.
#           - Use Bob's private key to decrypt the message.
#
# NOTE: 

def dh_get_key():
    """ Generate a DH key pair """
    G = EcGroup()
    priv_dec = G.order().random()
    pub_enc = priv_dec * G.generator()
    return (G, priv_dec, pub_enc)


def dh_encrypt(pub, message, aliceSig = None):
    """ Assume you know the public key of someone else (Bob), 
    and wish to Encrypt a message for them.
        - Generate a fresh DH key for this message.
        - Derive a fresh shared key.
        - Use the shared key to AES_GCM encrypt the message.
        - Optionally: sign the message with Alice's key.
    """
    
    ## YOUR CODE HERE
    G, priv_dec, pub_enc = dh_get_key()
    shared_key = pub.pt_mul(priv_dec)
    shared_key_hash = md5(shared_key.export()).digest()

    iv, ciphertxt, tag = encrypt_message(shared_key_hash, message)

    signature = None
    if aliceSig:
        signature = ecdsa_sign(G, priv_dec, message)

    encrypted = (iv, ciphertxt, tag, signature, pub_enc)
    return encrypted

def dh_decrypt(priv, ciphertext, aliceVer = None):
    """ Decrypt a received message encrypted using your public key, 
    of which the private key is provided. Optionally verify 
    the message came from Alice using her verification key."""
    ## YOUR CODE HERE
    G = EcGroup()
    iv, ciphertxt, tag, signature, pub_enc = ciphertext
    shared_key = pub_enc.pt_mul(priv)
    shared_key_hash = md5(shared_key.export()).digest()
    plaintext = decrypt_message(shared_key_hash, iv, ciphertxt, tag)

    signature_verified = None
    if signature and aliceVer:
        signature_verified = ecdsa_verify(G, pub_enc, plaintext, signature)

    return (plaintext.decode("utf8"), signature_verified)

## NOTE: populate those (or more) tests
#  ensure they run using the "py.test filename" command.
#  What is your test coverage? Where is it missing cases?
#  $ py.test-2.7 --cov-report html --cov Lab01Code Lab01Code.py 

def test_encrypt():
    G, priv_dec, pub_enc = dh_get_key()
    plain_text = "test"*100

    # Encrypt without a signature
    iv, ciphertext, tag, signature, pub_enc = dh_encrypt(pub_enc, plain_text, None)
    assert ciphertext != plain_text
    assert len(ciphertext) == len(plain_text)
    assert signature == None

    # Encrypt with a signature
    iv, ciphertext, tag, signature, pub_enc = dh_encrypt(pub_enc, plain_text, True)
    assert ciphertext != plain_text
    assert len(ciphertext) == len(plain_text)
    assert signature != None
    assert len(iv) == 16


def test_decrypt():
    G, priv_dec, pub_enc = dh_get_key()
    plain_text = "SomeWeirdTestingCode9999$"*100
    encrypted = dh_encrypt(pub_enc, plain_text, True)

    # Now go and decrypt to ensure the data matches
    dec_message, sig_verified = dh_decrypt(priv_dec, encrypted, True)

    print "dec, plain"
    print dec_message
    print plain_text

    assert len(dec_message) == len(plain_text)
    assert dec_message == plain_text

def test_fails():
    from pytest import raises
    G, priv_dec, pub_enc = dh_get_key()
    plain_text = "SomeWeirdTestingCode9999$"*100

    # Encrypt with a signature
    message = dh_encrypt(pub_enc, plain_text, True)
    
    plain_text_bad = "toTest || !ToTest$"*100
    message_2 = dh_encrypt(pub_enc, plain_text_bad, True)

    # Message: (iv, ciphertext, tag, signature, pub_enc)
    message_new = (message[0], message[1], message[2], message_2[3], message[4])

    # Now decrypt to be sure the data matches
    dec_message, sig_verified = dh_decrypt(priv_dec, message_new, True)

    assert dec_message == plain_text
    assert sig_verified == False        # As we inserted the signature from message 2 in the message

    with raises(Exception) as excinfo:
        fake_message = (message[0], urandom(len(message[1])), message[2], message[3], message[4])
        dh_decrypt(priv_dec, fake_message)
    assert 'decryption failed' in str(excinfo.value)

    with raises(Exception) as excinfo:
        dh_decrypt(priv_dec, (message[0], message[1], urandom(len(message[2])), message[3], message[4]) )
    assert 'decryption failed' in str(excinfo.value)

    with raises(Exception) as excinfo:
        dh_decrypt(priv_dec, (urandom(len(message[0])), message[1], message[2], message[3], message[4]))
    assert 'decryption failed' in str(excinfo.value)

    with raises(Exception) as excinfo:
        dh_decrypt(priv_dec, (message[0], message[1], message[2], message[3], G.order().random() * G.generator()))
    assert 'decryption failed' in str(excinfo.value)

    with raises(Exception) as excinfo:
        dh_decrypt(G.order().random(), (message[0], message[1], message[2], message[3], message[4]))
    assert 'decryption failed' in str(excinfo.value)

#####################################################
# TASK 6 -- Time EC scalar multiplication
#             Open Task.
#           
#           - Time your implementations of scalar multiplication
#             (use time.clock() for measurements)for different 
#              scalar sizes)
#           - Print reports on timing dependencies on secrets.
#           - Fix one implementation to not leak information.

def time_scalar_mul():
    pass
