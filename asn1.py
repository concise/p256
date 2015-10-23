#
# (int | bytes | tuple) -> TypeError | bytes
#

def encode_a_value(value):
    if type(value) is int:
        return encode_an_INTEGER(value)
    if type(value) is bytes:
        return encode_an_OCTETSTRING(value)
    if type(value) is tuple:
        return encode_a_SEQUENCE(value)
    raise TypeError

def encode_length(length):
    if 0 <= length <= 0x7f:
        return unsigned_integer_encode(length)
    else:
        return encode_long_length(length)

def encode_long_length(length):
    length_octets = unsigned_integer_encode(length)
    prefix = unsigned_integer_encode(0b10000000 | len(length_octets))
    return prefix + length_octets

def encode_an_INTEGER(value):
    assert type(value) is int
    contents_octets = twoscomplement_signed_integer_encode(value)
    length_octets = encode_length(len(contents_octets))
    identifier_octets = b'\x02'
    return identifier_octets + length_octets + contents_octets

def encode_an_OCTETSTRING(value):
    assert type(value) is bytes
    contents_octets = value
    length_octets = encode_length(len(contents_octets))
    identifier_octets = b'\x04'
    return identifier_octets + length_octets + contents_octets

def encode_a_SEQUENCE(value):
    assert type(value) is tuple
    contents_octets = b''
    for val in value:
        contents_octets += encode_a_value(val)
    length_octets = encode_length(len(contents_octets))
    identifier_octets = b'\x30'
    return identifier_octets + length_octets + contents_octets

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

def decode_to_value(stream):
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
    length = unsigned_integer_decode(length_octets)
    return length, tail_octets

def decode_to_INTEGER_value_and_tail(stream):
    assert type(stream) is bytes and len(stream) >= 1 and stream[0] == 0x02
    stream = stream[1:]
    length, contents, tail = decode_to_length_contents_and_tail(stream)
    try:
        value = twoscomplement_signed_integer_decode(contents)
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

def twoscomplement_signed_integer_encode(x):
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

def twoscomplement_signed_integer_decode(x):
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

def unsigned_integer_encode(x):
    assert type(x) is int and x >= 0
    nbytes = 1; bound = 256
    while not (bound > x):
        nbytes += 1; bound <<= 8
    return int.to_bytes(x, length=nbytes, byteorder='big', signed=False)

def unsigned_integer_decode(x):
    assert type(x) is bytes and len(x) > 0 and (len(x) == 1 or x[0] != 0)
    return int.from_bytes(x, byteorder='big', signed=False)


def H2B(h):
    # H2B('010203') == b'\x01\x02\x03'
    return bytes.fromhex(h)

def B2H(b):
    # B2H(b'\x01\x02\x03') == '010203'
    import codecs
    return codecs.encode(b, 'hex').decode()
