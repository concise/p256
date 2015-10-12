#
# Export these symbols
#
#       G
#       n
#       add
#       mul
#

p  = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
a  = -3
b  = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
xG = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
yG = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
G  = xG, yG
n  = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551

QUAD_b = (4 * b) % p

POINT_AT_INFINITY = None

def SELF_TEST():
    k1 = 0xcc496a11d4cfc0958657918858041182ac6a9570df89fd21f486fda95fd0dc4d
    x1 = 0x2b953776b6c5bf472bc8dc016004aad9eb264b80b1e7b030ffd21df1632ab5ea
    y1 = 0xc9fd1ce99f3abee0cd212ffdd399a58bbc60466db2e8f4badfda8d53be4f8073
    k2 = 0xf0bbbbf1048810db67440edbbb4040009bdc01e0cd00b10973f2387c17907cf5
    x2 = 0xa8cc7306c34dbfbc4164c1ec3a1734e3dbece5b611a09496196098746c3178f7
    y2 = 0xdb53860d50d88205f928b8450bc8ad2f3296690c9ed6f2025d6333f2fb302862
    k3 = 0xa5b6109e1622bfaff803a3dd53397f61d64ba9fb6499d5b5aa38201f71a2244b
    x3 = 0x5392a2b409193094bb8ce8b6c53f10496b3a093f82728a93fd81f6231b70458a
    y3 = 0xc28201bd1d37458776b20807a5106f3432e7289b2294b04b22817284edfae7d3
    assert mul(k1, G) == (x1, y1)
    assert mul(k2, G) == (x2, y2)
    assert mul(k3, G) == (x3, y3)
    print('All tests pass')

def BITSTRING(k):
    return '{:b}'.format(k)
    # BITSTRING(0b11000101) == '11000101'
    # BITSTRING(0b10001011) == '10001011'

def INV(i):
    return pow(i, p - 2, p)

def POINT_ADDITION(P1, P2):
    (x1, y1), (x2, y2) = P1, P2
    v = ((y2 - y1) * INV(x2 - x1)) % p
    x3 = (v * v - x1 - x2) % p
    y3 = (v * (x1 - x3) - y1) % p
    return x3, y3

def POINT_DOUBLING(P1):
    x1, y1 = P1
    w = ((3 * x1 * x1 + a) * INV(2 * y1)) % p
    x4 = (w * w - 2 * x1) % p
    y4 = (w * (x1 - x4) - y1) % p
    return x4, y4
    # Doubling will never yield the point at infinity if n is an odd integer.

def POINT_DOUBLING_INTO_X_Z_COORD(P1):
    x1, y1 = P1
    W = (4 * (y1 * y1 % p)) % p
    T = ((3 * (x1 * x1 % p)) + a) % p
    X = (T * T - W * (2 * x1)) % p
    return X, W

def add(P1, P2):
    if P1 == POINT_AT_INFINITY:
        return P2
    if P2 == POINT_AT_INFINITY:
        return P1
    if P1[0] != P2[0]:
        return POINT_ADDITION(P1, P2)
    if P1[0] == P2[0] and P1[1] == P2[1]:
        return POINT_DOUBLING(P1)
    if P1[0] == P2[0] and P1[1] != P2[1]:
        return POINT_AT_INFINITY

def mul_slow(k, P):
    k %= n
    R1 = POINT_AT_INFINITY
    R2 = P
    for ki in BITSTRING(k):
        if ki == '1':
            R1 = add(R1, R2)
            R2 = add(R2, R2)
        else:
            R2 = add(R2, R1)
            R1 = add(R1, R1)
    return R1

def mul(k, P):
    k %= n
    if k == 0 or P == POINT_AT_INFINITY:
        return POINT_AT_INFINITY
    if k == 1:
        return P
    if k == n - 1:
        return P[0], (-P[1] % p)
    return CO_Z_MONTGOMERY_LADDER_SCALAR_MUL(k, P)

def CO_Z_MONTGOMERY_LADDER_SCALAR_MUL(k, P):
    # { P, P + P } ~= (X1 : X2 : Z)
    xP, yP = P
    X2, Z  = POINT_DOUBLING_INTO_X_Z_COORD(P)
    X1     = (xP * Z) % p
    # TD=(xP*Z), Ta=(a*Z**2), Tb=(4*b*Z**3)
    TD = X1
    Ta = (Z  * Z) % p
    Tb = (Ta * Z) % p
    Ta = (Ta * a) % p
    Tb = (Tb * QUAD_b) % p
    # Montgomery ladder
    for ki in BITSTRING(k)[1:]:
        if ki == '1':
            X1, X2, TD, Ta, Tb = CO_Z_DIFF_ADD_DBL(X1, X2, TD, Ta, Tb)
        else:
            X2, X1, TD, Ta, Tb = CO_Z_DIFF_ADD_DBL(X2, X1, TD, Ta, Tb)
    # From { R1, R2 } ~= (X1 : X2 : Z) to R1 ~= (X : Y : Z)
    X, Y, Z = CO_Z_RECOVERY(X1, X2, TD, Ta, Tb, xD=xP, yD=yP)
    iZ = INV(Z)
    return (X * iZ) % p, (Y * iZ) % p

def CO_Z_DIFF_ADD_DBL(X1, X2, TD, Ta, Tb):
    # Using (X1 : X2 : Z) representation for a pair of two points, convert
    # (R1, R2) into (R1 + R2, R2 + R2) using (10 M + 5 S + 13 add).
    R2 = (X1 - X2) % p; R1 = (R2 * R2) % p; R2 = (X2 * X2) % p;
    R3 = (R2 - Ta) % p; R4 = (R3 * R3) % p; R5 = (X2 + X2) % p;
    R3 = (R5 * Tb) % p; R4 = (R4 - R3) % p; R5 = (R5 + R5) % p;
    R2 = (R2 + Ta) % p; R3 = (R5 * R2) % p; R3 = (R3 + Tb) % p;
    R5 = (X1 + X2) % p; R2 = (R2 + Ta) % p; R2 = (R2 - R1) % p;
    X2 = (X1 * X1) % p; R2 = (R2 + X2) % p; X2 = (R5 * R2) % p;
    X2 = (X2 + Tb) % p; X1 = (R3 * X2) % p; X2 = (R1 * R4) % p;
    R2 = (R1 * R3) % p; R3 = (R2 * Tb) % p; R4 = (R2 * R2) % p;
    R1 = (TD * R2) % p; R2 = (Ta * R4) % p; Tb = (R3 * R4) % p;
    X1 = (X1 - R1) % p; TD = R1; Ta = R2;
    return X1, X2, TD, Ta, Tb

def CO_Z_RECOVERY(X1, X2, TD, Ta, Tb, xD, yD):
    # Convert an (X1 : X2 : Z) representation for the pair (R1, R2) with the
    # difference R2 - R1 == D already known into an (X : Y : Z) representation
    # for the point R1 using (10 M + 3 S + 8 add).
    R1 = (TD * X1) % p; R2 = (R1 + Ta) % p; R3 = (X1 + TD) % p;
    R4 = (R2 * R3) % p; R3 = (X1 - TD) % p; R2 = (R3 * R3) % p;
    R3 = (R2 * X2) % p; R4 = (R4 - R3) % p; R4 = (R4 + R4) % p;
    R4 = (R4 + Tb) % p; R2 = (TD * TD) % p; R3 = (X1 * R2) % p;
    R1 = (xD * R3) % p; R3 = (yD + yD) % p; R3 = (R3 + R3) % p;
    X1 = (R3 * R1) % p; R1 = (R2 * TD) % p; Z  = (R3 * R1) % p;
    R2 = (xD * xD) % p; R3 = (R2 * xD) % p; X2 = (R3 * R4) % p;
    return X1, X2, Z

#
# References
#
#       http://safecurves.cr.yp.to/
#       https://www.hyperelliptic.org/EFD/g1p/auto-shortw.html
#       http://www.secg.org/sec1-v2.pdf
#       http://www.secg.org/sec2-v2.pdf
#       http://csrc.nist.gov/groups/ST/toolkit/documents/dss/NISTReCur.pdf
#       http://joye.site88.net/papers/HJS11coz.pdf
#
