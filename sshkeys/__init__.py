from binascii import hexlify
from base64 import b64decode, b64encode
from hashlib import md5
from struct import unpack


def iter_prefixed(data):
    while data:
        # get next prefix
        l = unpack('!I', data[:4])[0]
        packet, data = data[4:4+l], data[4+l:]
        yield packet


class Key(object):
    def __init__(self, data, comment):
        self.data = data
        self.comment = comment

    @property
    def data(self):
        return self._data

    @data.setter
    def data(self, val):
        self._data = val
        self._fingerprint = None
        self._type = None

    @property
    def length(self):
        raise NotImplementedError('Key length check not implemented')

    @property
    def type(self):
        if not self._type:
            self._type = iter_prefixed(self.data).next()

        return self._type

    @property
    def fingerprint(self):
        if not self._fingerprint:
            self._fingerprint = md5(self._data).digest()
        return self._fingerprint

    @property
    def readable_fingerprint(self):
        h = hexlify(self.fingerprint)
        return ':'.join(h[i:i+2] for i in range(0, len(h), 2))

    @classmethod
    def from_pubkey_line(cls, line):
        fields = line.split()
        if not len(fields) == 3:
            raise ValueError('Could not parse key, expected 3 fields, got {}'
                             .format(len(fields)))

        type_str, data64, comment = fields
        data = b64decode(data64)

        key_type = iter_prefixed(data).next()

        if key_type == 'ssh-rsa':
            key_class = RSAKey
        elif key_type == 'ssh-dss':
            key_class = DSAKey
        elif key_type.startswith('ecdsa-'):
            key_class = ECDSAKey
        else:
            raise ValueError('Unknown key type {}'.format(key_type))

        return key_class(b64decode(data64), comment)

    @classmethod
    def from_pubkey_file(cls, file):
        if hasattr(file, 'read'):
            return cls.from_pubkey_line(file.read())

        return cls.from_pubkey_line(open(file).read())

    def to_pubkey_line(self):
        return '{} {} {}'.format(
            self.type,
            b64encode(self.data),
            self.comment,
        )


class RSAKey(Key):
    @property
    def length(self):
        prefix, exp, n = [p for p in iter_prefixed(self.data)]

        l = (len(n)-1) * 8

        # the first bit is the sign and should always be 0
        # all bits below the highest non-0 bit are part of the modulus
        tmp = ord(n[0])
        while tmp:
            tmp >>= 1
            l += 1

        return l


class DSAKey(Key):
    length = 1024


class ECDSAKey(Key):
    @property
    def length(self):
        type, curve, data = [p for p in iter_prefixed(self.data)]
        if not curve.startswith('nistp'):
            raise NotImplementedError('Cannot determine length of curve')
        return int(curve[5:])
