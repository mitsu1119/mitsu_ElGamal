# Coding: utf-8
import sys
import random

#
# Miller-Rabin test
#
def MR(n):
    if n == 2:
        return True
    if n == 1:
        return False
    if n & 1 == 0:
        return False

    d = (n - 1) >> 1
    while d & 1 == 0:
        d //= 2

    for i in range(100):
        a = random.randint(1, n - 1)
        x = pow(a, d, n)
        t = d

        while t != n - 1 and x != 1 and x != n - 1:
            x = pow(x, 2, n)
            t *= 2

        if x != n - 1 and x & 1 == 0:
            return False

    return True

#
# generate prime number
#
def genPrime(bit_size):
    while True:
        buf = pow(2, bit_size - 1)
        # 2 * randint(0, (2^n - 1 - 2^(n-1)) // 2) + 2^(n-1) + 1
        rand = 2 * random.randint(0, (buf - 1) // 2) + buf + 1
        if MR(rand):
            return rand

#
# generate safe prime number p
# q in P, if 2q+1 in P then 2q+1 is safe prime number
#
def genSafePrime(bit_size):
    while True:
        p = genPrime(256)
        if MR((p - 1) / 2):
            return p

# p is prime number.
# calculate a^-1 mod p
def prime_modinv(a, p):
    return pow(a, p - 2, p)

#
# key generation
# public key (q, g, h), private key (x)
#
def makeKey(bit_size):
    # if q isn't safe prime number, then this cipher become vulnerable
    q = genSafePrime(bit_size)
    g = random.randint(1, q - 1)
    x = random.randint(0, q - 1)
    h = pow(g, x, q)

    return q, g, h, x

#
# encrypto
#
def encryption(m):
    # 256 bit key
    q, g, h, x = makeKey(256)
    r = random.randint(0, q - 1)
    c1 = pow(g, r, q)
    c2 = ((m % q) * pow(h, r, q)) % q
    return c1, c2, x, q

#
# print Usage
#
def usage():
    print(" Usage: python elgamal.py [option]")
    print(" [option]")
    print("  -c : encrypt")
    print("  -d : decrypt")
    print("  -a : attack and get private key")

#
# decrypto
#
def decryption(c1, c2, x, q):
    # (c2 * (c1^x)^-1) mod q
    m = ((c2 % q) * pow(c1, x * (q - 2), q)) % q
    return m

if __name__ == "__main__":
    if len(sys.argv) == 1:
        usage()
        sys.exit()

    if sys.argv[1] == "-c":
        # encryption
        m = int(input("m: "))
        c1, c2, x, q = encryption(m)
        print("c1 = {}".format(c1))
        print("c2 = {}".format(c2))
        print("x = {}".format(x))
        print("q = {}".format(q))

    elif sys.argv[1] == "-d":
        # decryption
        c1 = int(input("c1: "))
        c2 = int(input("c2: "))
        x = int(input("x: "))
        q = int(input("q: "))

        m = decryption(c1, c2, x, q)
        print("m = {}".format(m))

    else:
        usage()
