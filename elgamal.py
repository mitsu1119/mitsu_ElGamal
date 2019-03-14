# Coding: utf-8
import sys
import random
from functools import reduce

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
        p = genPrime(bit_size)
        if MR((p - 1) / 2):
            return p

#
# extended gcd
#
def egcd(a, b):
    if b > 0:
        y, x, d = egcd(b, a % b)
        return x, y - a // b * x, d
    else:
        return 1, 0, a

#
# Chinese Remainder Theorem and solver
# solve Simultaneous congruences
# x = a1 mod m1, x = a2 mod m2, x = a3 mod m3 ...
#
def chineseRemainder(a, m):
    P = reduce(lambda x, y: x * y, a)
    res = 0
    for i in range(len(m)):
        x, y, d = egcd(a[i], P // a[i])
        res += y * P // a[i] * m[i]
        # print("Chinese: {}".format(res))
    return res % P


# p is prime number.
# calculate a^-1 mod p
def prime_modinv(a, p):
    return pow(a, p - 2, p)

#
# calc φ(p), p in P
# φ(n) is Euler's totient function
#
def prime_phip(p):
    return p - 1

#
# Baby-step Giant-step algorithm
# solve Discrete logarithm problem(g^x = y mod p)
# let x be im+j (m = ceiling(root(p)), 0 <= i,j <= m)
# g^j = y(g^-m)^i modp
# brute force i, j
#
def BsGs(g, y, p, q):
    m = int(q ** 0.5 + 1)

    # Baby-step
    bs = {}
    gj = 1
    for j in range(m):
        bs[gj] = j
        gj = (gj * g) % p

    # Giant-step
    gm = pow(prime_modinv(g, p), m, p)
    Y = y
    for i in range(m):
        if Y in bs:
            x = i * m + bs[Y]
            print("Found candidate: {}".format(x))
            return x
        else:
            Y = (Y * gm) % p
    print("Not found private key x ...")
    return - 1

#
# Pohling-Hellman algorithm
# break down complex Discrete logarithm problem into simple problems
# g^x = y mod p
#
def PH(p, g, y, phip_factors):
    bn = []
    for pk in phip_factors:
        phippk = prime_phip(p) // pk
        bk = BsGs(pow(g, phippk, p), pow(y, phippk, p), p, pk)
        bn.append(bk)

    print("bn: {}".format(bn))
    x = chineseRemainder(phip_factors, bn)
    return x


#
# key generation
# public key (q, g, h), private key (x)
#
def makeKey(bit_size):
    # if q isn't safe prime number, then this cipher becomes vulnerable
    # q = genSafePrime(bit_size)
    q = genSafePrime(bit_size)
    g = random.randint(1, q - 1)
    x = random.randint(0, q - 1)
    h = pow(g, x, q)

    return q, g, h, x

#
# encrypto
#
def encryption(m):
    # 128 bit key
    q, g, h, x = makeKey(128)
    r = random.randint(0, q - 1)
    c1 = pow(g, r, q)
    c2 = ((m % q) * pow(h, r, q)) % q
    return c1, c2, x, q

#
# decrypto
#
def decryption(c1, c2, x, q):
    # (c2 * (c1^x)^-1) mod q
    m = ((c2 % q) * pow(c1, x * (q - 2), q)) % q
    return m

#
# attack
#
def attack(c1, c2, q, g, h, phip):
    x = PH(q, g, h, phip)
    print("x: {}".format(x))
    m = decryption(c1, c2, x, q)
    return m

#
# print Usage
#
def usage():
    print(" Usage: python elgamal.py [option]")
    print(" [option]")
    print("  -c : encrypt")
    print("  -d : decrypt")
    print("  -a : attack and get private key")

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
        print("g = {}".format(g))
        print("h = {}".format(h))

    elif sys.argv[1] == "-d":
        # decryption
        c1 = int(input("c1: "))
        c2 = int(input("c2: "))
        x = int(input("x: "))
        q = int(input("q: "))

        m = decryption(c1, c2, x, q)
        print("m = {}".format(m))

    elif sys.argv[1] == "-a":
        # attack and get private key
        g = int(input("g: "))
        h = int(input("h: "))
        q = int(input("q: "))
        c1 = int(input("c1: "))
        c2 = int(input("c2: "))

        # φ(p) factors
        phip = []
        cnt = 1
        print("input -1 to stop")
        while True:
            pp = int(input("φ(p) factor{}: ".format(cnt)))
            if pp == -1:
                break
            phip.append(pp)
            cnt += 1
        m = attack(c1, c2, q, g, h, phip)
        print("m = {}".format(m))

    else:
        usage()
