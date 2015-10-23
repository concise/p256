#def B2H(x):
#    if type(x) is not bytes:
#        raise TypeError
#    import binascii
#    return binascii.hexlify(x).decode()

#def H2B(x):
#    try:
#        import binascii
#        return binascii.unhexlify(x.encode())
#    except:
#        raise TypeError from None

def B2H(b):
    if type(b) is not bytes:
        raise TypeError
    output = ''
    for octet in b:
        output += ('0123456789abcdef'[octet >> 4] +
                   '0123456789abcdef'[octet & 15])
    return output

def H2B(s):
    if not (type(s) is str and len(s) % 2 == 0 and
            all(map(lambda c: c in '0123456789abcdef', s))):
        raise TypeError
    output = b''
    for i in range(0, len(s) // 2):
        lhs = '0123456789abcdef'.index(s[2*i    ]) << 4
        rhs = '0123456789abcdef'.index(s[2*i + 1])
        output += bytes((lhs + rhs,))
    return output

################

def encode_uint(x):
    assert type(x) is int and x >= 0
    nbytes = 1; bound = 256
    while not (bound > x):
        nbytes += 1; bound <<= 8
    return int.to_bytes(x, length=nbytes, byteorder='big', signed=False)

def decode_uint(x):
    assert type(x) is bytes and len(x) > 0 and (len(x) == 1 or x[0] != 0)
    return int.from_bytes(x, byteorder='big', signed=False)

################

def encode_sint(x):
    def _twoscomplement_bit_length(x):
        assert type(x) is int
        if x < 0:
            x = -x - 1
        m = 0; n = 1
        while not (n > x):
            m += 1; n *= 2
        return m + 1
    def _twoscomplement_byte_length(x):
        assert type(x) is int
        bitlen = _twoscomplement_bit_length(x)
        return (bitlen // 8) + (bitlen % 8 != 0)
    assert type(x) is int
    l = _twoscomplement_byte_length(x)
    return int.to_bytes(x, length=l, byteorder='big', signed=True)

def decode_sint(x):
    def _is_shortest_twoscomplement_encoding(x):
        if type(x) is not bytes:
            return False
        if len(x) == 0:
            return False
        if len(x) == 1:
            return True
        if x[0] == 0b00000000 and (x[1] >> 7) == 0b0:
            return False
        if x[0] == 0b11111111 and (x[1] >> 7) == 0b1:
            return False
        return True
    assert _is_shortest_twoscomplement_encoding(x)
    return int.from_bytes(x, byteorder='big', signed=True)






# encoding marshalling   serialization   stringifying
# decoding unmarshalling deserialization parsing

def encode(x):
    if type(x) is int:
        V = encode_sint(x)
        L = encode_length(len(V))
        T = b'\x02'
        return T + L + V
    if type(x) is bytes:
        V = x
        L = encode_length(len(V))
        T = b'\x04'
        return T + L + V
    if type(x) is tuple:
        V = b''.join(map(encode, x))
        L = encode_length(len(V))
        T = b'\x30'
        return T + L + V
    raise TypeError

def encode_length(x):
    assert type(x) is int and x >= 0
    if 0 <= x <= 0x7f:
        length = encode_uint(x)
        return length
    else:
        length = encode_uint(x)
        lenlen = len(length)
        if not (0b00000001 <= lenlen <= 0b01111110):
            raise TypeError
        prefix = encode_uint(0b10000000 | lenlen)
        return prefix + length

#
# bytes -> TypeError | ((int | bytes | tuple), bytes)
#
#
# This decoder turns a bytes object into a *value*, where a *value* is
# either an int object, a bytes object, or a tuple object containing zero
# or more *values*.
#
# This is just a decoder for DER encoded ASN.1 values.  It only implements
# three ASN.1 data types now: INTEGER, OCTETSTRING, and SEQUENCE.
#

def decode(stream):
    value, tail = decode_to_value_and_tail(stream)
    if tail == b'':
        return value
    raise TypeError

def decode_to_value_and_tail(stream):
    if type(stream) is bytes and len(stream) >= 1:
        if stream[0] == 0x02:
            return decode_to_INTEGER_value_and_tail(stream)
        if stream[0] == 0x04:
            return decode_to_OCTETSTRING_value_and_tail(stream)
        if stream[0] == 0x30:
            return decode_to_SEQUENCE_value_and_tail(stream)
    raise TypeError

def decode_to_length_contents_and_tail(stream):
    length, stream = decode_to_length_and_tail(stream)
    if len(stream) < length:
        raise TypeError
    return length, stream[:length], stream[length:]

def decode_to_length_and_tail(stream):
    assert type(stream) is bytes
    if len(stream) == 0:
        raise TypeError
    if stream[0] in {0x80, 0xff}:
        raise TypeError
    if 0x00 <= stream[0] <= 0x7f:
        return stream[0], stream[1:]
    if 0x81 <= stream[0] <= 0xfe:
        return decode_to_long_length_and_tail(stream)

def decode_to_long_length_and_tail(stream):
    length_of_length_octets = stream[0] & 0b01111111
    stream = stream[1:]
    if len(stream) < length_of_length_octets:
        raise TypeError
    length_octets = stream[:length_of_length_octets]
    tail_octets = stream[length_of_length_octets:]
    if len(length_octets) == 1 and length_octets[0] < 0x80:
        raise TypeError
    if length_octets[0] == 0x00:
        raise TypeError
    length = decode_uint(length_octets)
    return length, tail_octets

def decode_to_INTEGER_value_and_tail(stream):
    assert type(stream) is bytes and len(stream) >= 1 and stream[0] == 0x02
    stream = stream[1:]
    length, contents, tail = decode_to_length_contents_and_tail(stream)
    try:
        value = decode_sint(contents)
    except AssertionError:
        raise TypeError from None
    return value, tail

def decode_to_OCTETSTRING_value_and_tail(stream):
    assert type(stream) is bytes and len(stream) >= 1 and stream[0] == 0x04
    stream = stream[1:]
    length, contents, tail = decode_to_length_contents_and_tail(stream)
    return contents, tail

def decode_to_SEQUENCE_value_and_tail(stream):
    assert type(stream) is bytes and len(stream) >= 1 and stream[0] == 0x30
    stream = stream[1:]
    length, contents, tail = decode_to_length_contents_and_tail(stream)
    value = ()
    while len(contents) != 0:
        v, contents = decode_to_value_and_tail(contents)
        value += (v,)
    return value, tail
