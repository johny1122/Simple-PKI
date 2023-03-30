# https://crypto.stackexchange.com/questions/58292/schnorr-signature-using-discrete-logarithm-problem-with-python-implementation

from hashlib import sha256
from random import randint


def hashThis(r, M):
    hash = sha256()
    hash.update(str(r).encode())
    hash.update(M.encode())
    return int(hash.hexdigest(), 16)


# Notation
# generator g
g = 2

# Prime q (for educational purpose I use explicitly a small prime number - for cryptographic purposes this
# would have to be much larger)
q = 2695139

# Key generation
# Private signing key x
x = 32991
# calculate public verification key y
y = pow(g, x, q)

# Signing
M = "This is the message"
k = randint(1, q - 1)
r = pow(g, k, q)
e = hashThis(r, M) % q  # part 1 of signature
s = (k - (x * e)) % (q - 1)  # part 2 of signature

# Verification

rv = (pow(g, s, q) * pow(y, e, q)) % q
ev = hashThis(rv, M) % q

print("e " + str(e) + " should equal ev " + str(ev))
# e 2241534 should equal ev 2462540
