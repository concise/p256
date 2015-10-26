# encoding      vs decoding
# marshalling   vs unmarshalling
# serialization vs deserialization
# stringifying  vs parsing

def B2H(x):
  if not (type(x) is bytes):
    raise TypeError
  return bytes.hex(x)

def H2B(x):
  if not (type(x) is str and len(x) % 2 == 0 and
  all(map(lambda c: c in '0123456789abcdef', x))):
    raise TypeError
  return bytes.fromhex(x)

###############################################################################

def encode_uint(x):
  if not (type(x) is int and x >= 0):
    raise TypeError
  nbytes = 1; bound = 256
  while not (bound > x):
    nbytes += 1; bound <<= 8
  return int.to_bytes(x, length=nbytes, byteorder='big', signed=False)

def decode_uint(x):
  if not (type(x) is bytes and len(x) >= 1 and (len(x) == 1 or x[0] != 0)):
    raise TypeError
  return int.from_bytes(x, byteorder='big', signed=False)

###############################################################################

def encode_sint(x):
  if not (type(x) is int):
    raise TypeError
  length = _twoscomplement_byte_length(x)
  return int.to_bytes(x, length=length, byteorder='big', signed=True)

def decode_sint(x):
  if not _is_twoscomplement_encoded(x):
    raise TypeError
  return int.from_bytes(x, byteorder='big', signed=True)

def _twoscomplement_bit_length(x):
  if x < 0:
    x = -x - 1
  nbits = 0; bound = 1
  while not (bound > x):
    nbits += 1; bound <<= 1
  return nbits + 1

def _twoscomplement_byte_length(x):
  bitlen = _twoscomplement_bit_length(x)
  return (bitlen // 8) + (bitlen % 8 != 0)

def _is_twoscomplement_encoded(x):
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

###############################################################################

def encode_asn1_length(x):
  if not (type(x) is int and x >= 0):
    raise TypeError
  if 0x00 <= x <= 0x7f:
    return _encode_asn1_short_length(x)
  else:
    return _encode_asn1_long_length(x)

def _encode_asn1_short_length(x):
  length = encode_uint(x)
  return length

def _encode_asn1_long_length(x):
  length = encode_uint(x)
  lenlen = len(length)
  if not (0b00000001 <= lenlen <= 0b01111110):
    raise TypeError # PRACTICALLY SHOULD NEVER HAPPEN
  prefix = encode_uint(0b10000000 | lenlen)
  return prefix + length

def encode_asn1_INTEGER(x):
  if not (type(x) is int):
    raise TypeError
  V = encode_sint(x)
  L = encode_asn1_length(len(V))
  T = b'\x02'
  return T + L + V

def encode_asn1_BITSTRING(x):
  if not (type(x) is bytes):
    raise TypeError
  V = b'\x00' + x
  L = encode_asn1_length(len(V))
  T = b'\x03'
  return T + L + V

def encode_asn1_OCTETSTRING(x):
  if not (type(x) is bytes):
    raise TypeError
  V = x
  L = encode_asn1_length(len(V))
  T = b'\x04'
  return T + L + V

def encode_asn1_SEQUENCE(x):
  if not (type(x) is tuple and all(map(lambda e: type(e) is bytes, x))):
    raise TypeError
  V = b''.join(x)
  L = encode_asn1_length(len(V))
  T = b'\x30'
  return T + L + V

###############################################################################

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
    value = decode_sint(contents)
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
