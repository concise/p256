#!/usr/bin/env python3

import sys

#
# Export these symbols
#
#       G
#       n
#       add
#       mul
#       point_to_octetstring
#       point_from_octetstring
#

p  = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
a  = -3
b  = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
xG = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
yG = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
G  = xG, yG
n  = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551

# a, b, xG, and yG are elements in GF(p)

b_QUAD = (4 * b) % p

p_LEN = (lambda _: (_ // 8) + (1 if _ % 8 > 0 else 0))(p.bit_length())

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

def point_from_octetstring(octetstring):
    if len(octetstring) == 1 and octetstring[0] == 0x00:
        return POINT_AT_INFINITY
    elif len(octetstring) == 1 + p_LEN and octetstring[0] in {0x02, 0x03}:
        y_parity = octetstring[0] & 1
        x = int.from_bytes(octetstring[1:33], byteorder='big', signed=False)
        y = y_candidates_from_x(x)[y_parity]
        return x, y
    elif len(octetstring) == 1 + p_LEN + p_LEN and octetstring[0] == 0x04:
        x = int.from_bytes(octetstring[1:33], byteorder='big', signed=False)
        y = int.from_bytes(octetstring[33:65], byteorder='big', signed=False)
        require_on_curve(x, y)
        return x, y
    else:
        raise ValueError

def y_candidates_from_x(x):
    # Get a pair (y0, y1) such that both (x, y0) and (x, y1) are points on the
    # curve, where y0 is an even integer and y1 is an odd integer.
    #
    # In GF(p):
    #
    #   x ** p         === x
    #   x ** (p+1)     === x ** 2
    #   x ** ((p+1)/2) === x
    #   x ** ((p+1)/4) === y
    #   y ** 2         === x
    #
    # assuming p === 3 (mod 4)
    #
    assert p & 3 == 3
    y_squared = (x * x * x + a * x + b) % p
    y = pow(y_squared, (p + 1) // 4, p)
    if y * y % p != y_squared:
        raise ValueError
    return (y, -y % p) if (y & 1 == 0) else (-y % p, y)

def require_on_curve(x, y):
    if on_curve(x, y):
        pass
    else:
        raise ValueError

def on_curve(x, y):
    lhs = (y * y) % p
    rhs = (x * x * x + a * x + b) % p
    return lhs == rhs

def point_to_octetstring(point, compressed=False):
    if point == POINT_AT_INFINITY:
        return b'\x00'
    elif compressed == False:
        XX = point[0].to_bytes(length=p_LEN, byteorder='big', signed=False)
        YY = point[1].to_bytes(length=p_LEN, byteorder='big', signed=False)
        return b'\x04' + XX + YY
    else:
        XX = point[0].to_bytes(length=p_LEN, byteorder='big', signed=False)
        y_parity = point[1] & 1
        return (b'\x02', b'\x03')[y_parity] + XX

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
    # This requires that we have: x2 !== x1 mod n

def POINT_DOUBLING(P1):
    x1, y1 = P1
    w = ((3 * x1 * x1 + a) * INV(2 * y1)) % p
    x4 = (w * w - 2 * x1) % p
    y4 = (w * (x1 - x4) - y1) % p
    return x4, y4
    # This requires that we have: 2 * y1 !== 0 mod n
    # Doubling a nonzero will never yield a zero if n is an odd integer.

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

def mul(k, P):
    return mul_fast(k, P)

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

def mul_fast(k, P):
    k %= n
    if k == 0 or P == POINT_AT_INFINITY:
        return POINT_AT_INFINITY
    if k == 1:
        return P
    if k == n - 1:
        return P[0], (-P[1] % p)
    return CO_Z_MONTGOMERY_LADDER_SCALAR_MUL(k, P)

def CO_Z_MONTGOMERY_LADDER_SCALAR_MUL(k, P):
    X1, X2, TD, Ta, Tb, xD, yD = CO_Z_SETUP(P)
    for ki in BITSTRING(k)[1:]:
        if ki == '1':
            X1, X2, TD, Ta, Tb = CO_Z_DIFF_ADD_DBL(X1, X2, TD, Ta, Tb)
        else:
            X2, X1, TD, Ta, Tb = CO_Z_DIFF_ADD_DBL(X2, X1, TD, Ta, Tb)
    return CO_Z_RECOVERY(X1, X2, TD, Ta, Tb, xD, yD)

def CO_Z_SETUP(P):
    # Let (X1, X2, TD, Ta, Tb, xD, yD) represent
    # the pair of two points R1 and R2 = R1 + D.
    #
    #       D  = ( xD     ,  yD )
    #       R1 = ( X1 / Z ,  ?  )
    #       R2 = ( X2 / Z ,  ?  )
    #       TD = xD    * Z
    #       Ta = a     * Z * Z
    #       Tb = 4 * b * Z * Z * Z
    #
    xD, yD = P
    X2, Z = POINT_DOUBLING_INTO_X_Z_COORD(P)
    X1 = ( xD * Z      ) % p
    Ta = ( Z  * Z      ) % p
    Tb = ( Ta * Z      ) % p
    Ta = ( Ta * a      ) % p
    Tb = ( Tb * b_QUAD ) % p
    TD = X1
    return X1, X2, TD, Ta, Tb, xD, yD

def CO_Z_RECOVERY(X1, X2, TD, Ta, Tb, xD, yD):
    # (Q, Q + D) ~= (X1:X2:Z) -> Q ~= (X:Y:Z) -> Q = (x, y)
    X, Y, Z = CO_Z_DIFF_COORD_TO_XZ_COORD(X1, X2, TD, Ta, Tb, xD, yD)
    iZ = INV(Z)
    return (X * iZ) % p, (Y * iZ) % p

def CO_Z_DIFF_ADD_DBL(X1, X2, TD, Ta, Tb):
    # Using (X1:X2:Z) representation for a pair of two points, convert the
    # pair (R1, R2) into (R1 + R2, R2 + R2) using (10 M + 5 S + 13 add).
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

def CO_Z_DIFF_COORD_TO_XZ_COORD(X1, X2, TD, Ta, Tb, xD, yD):
    # Convert an (X1:X2:Z) representation for the pair (R1, R1 + D) into an
    # (X:Y:Z) representation for R1 using (10 M + 3 S + 8 add).
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



#
# TODO
#
# * Types
#
#       BOOLEAN       {TRUE, FALSE}   bool
#       OCTETSTRING   {0..255}*       bytes
#       INTEGER       Z               int
#       ECPOINT       E               tuple, int, and NoneType
#       EXCEPTION                     BaseException
#
# * Operations on the elliptic curve cyclic group P-256
#
#       ZERO_POINT    : E
#       BASE_POINT    : E
#       eq            : E x E     -> {TRUE, FALSE}
#       neg           : E         -> E
#       add           : E x E     -> E
#       mul           : Z x E     -> E
#       xcoord2int    : E         -> Z
#       deserialize   : {0..255}* -> E
#       serialize     : E         -> {0..255}*
#
# * Extract public key octet string from an X.509 version 3 certificate
#
# * ECDSA signature verification
#

def main():
    args = tuple(sys.argv)[1::]
    if len(args) == 3 and args[0] == 'mul':
        main_mul(*args[1::])
    elif len(args) == 3 and args[0] == 'add':
        main_add(*args[1::])
    else:
        sys.exit(1)

def main_mul(scalar_hexstr, point_hexstr):
    try:
        scalar = int(scalar_hexstr, 16)
        point = point_from_octetstring(bytes.fromhex(point_hexstr))
        result_point = mul(scalar, point)
        sys.stdout.buffer.write(point_to_octetstring(result_point))
    except:
        sys.exit(1)

def main_add(point1_hexstr, point2_hexstr):
    try:
        point1 = point_from_octetstring(bytes.fromhex(point1_hexstr))
        point2 = point_from_octetstring(bytes.fromhex(point2_hexstr))
        result_point = add(point1, point2)
        sys.stdout.buffer.write(point_to_octetstring(result_point))
    except:
        sys.exit(1)

if __name__ == '__main__':
    main()

'''

Example usage:

$ p256.py mul 9cbbd852aefdba71d2390201451a869933786c7eafe827e8900265a9dba22d2e 044d75c0d632ebbe8e1941e31a0838434874952af2b8f500a9c906bc8a7a0f5aba224e92b22159e2b7543dff1c352004d71efdeac802fe479e936156238f711b79 | xxd -p | tr -d \\n
04cd6f0c68fcb7e7840863ba502f28b0c8809bd998102fb1fa04a7ace6353a7788c0f48b0db6e9899cfb79dcb47a938d8fe8632a6f2e72c37babd654a93eccb504

$ p256.py add 04baa80d40d267d468c5e8aa61d7a64c3649b495037125b024eefd989dff7ce8fd2414aa7e82b7081b2f96b6a424d94438382ec0c336f743507baa523dd030f1b2 044d6e59ba83776d5f341bc6396f8b4f4fef35583cdd0b3031c317fda066211d4dc93c2f8a7d7f18a2d8e24271fa39ca4abde856c52046b1beaaf2e01b3ab463df | xxd -p | tr -d \\n
047645cf8e511211d388361a5b7b88920784e1e7a1059bc56967fc56b07c5d9423685c580d119f2d06896883a3efd23883a06a0dcfb776f78c71f02e2c03fac536

'''
