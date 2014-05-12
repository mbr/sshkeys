from binascii import hexlify
from base64 import b64decode, b64encode
from collections import OrderedDict
from hashlib import md5
import re
from struct import unpack

from six import byte2int


def iter_prefixed(data):
    while data:
        # get next prefix
        l = unpack('!I', data[:4])[0]
        packet, data = data[4:4+l], data[4+l:]
        yield packet


class Key(object):
    def __init__(self, data, comment=None, options=None):
        self.data = data
        self.comment = comment
        self.options = options or OrderedDict()

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
            self._type = next(iter_prefixed(self.data))

        return self._type.decode('ascii')

    @property
    def fingerprint(self):
        if not self._fingerprint:
            self._fingerprint = md5(self._data).digest()
        return self._fingerprint

    @property
    def readable_fingerprint(self):
        h = hexlify(self.fingerprint).decode()
        return ':'.join(h[i:i+2] for i in range(0, len(h), 2))

    @classmethod
    def from_pubkey_line(cls, line):
        quoted = False
        fields = []
        start = 0
        line = line.strip()
        for i, c in enumerate(line):
            if quoted:
                if c == '"':
                    quoted = False
                continue

            if c == '"':
                quoted = True
                continue

            if c == ' ':
                fields.append(line[start:i])
                start = i+1

        fields.append(line[start:])

        if len(fields) > 4:
            raise ValueError('Could not parse key, too many fields({}).'
                             .format(len(fields)))

        if len(fields) < 2:
            raise ValueError('Could not parse key, too few fields({}).'
                             .format(len(fields)))

        opt_str = None
        comment = None
        if len(fields) == 2:
            type_str, data64 = fields
        elif len(fields) == 4:
            opt_str, type_str, data64, comment = fields
        if len(fields) == 3:
            # we could be missing options or the comment
            # try to decode base64 data from either the 2nd or 3rd field
            if fields[1].startswith('ssh-') or fields[1].startswith('ecdsa'):
                # 2nd field is type string, there's a comment preprepended
                opt_str, type_str, data64 = fields
            else:
                type_str, data64, comment = fields

        data = b64decode(data64)
        key_type = next(iter_prefixed(data))

        if key_type == b'ssh-rsa':
            key_class = RSAKey
        elif key_type == b'ssh-dss':
            key_class = DSAKey
        elif key_type.startswith(b'ecdsa-'):
            key_class = ECDSAKey
        else:
            raise ValueError('Unknown key type {}'.format(key_type))

        # parse options
        PAIR_RE = re.compile(r'([A-Za-z0-9-]+)(="[^"]*"|[^"\s,])?,')

        options = OrderedDict()
        if opt_str:
            for k, v in PAIR_RE.findall(opt_str + ','):
                if not v.startswith('='):
                    options[k] = True
                elif v.startswith('="'):
                    options[k] = v[2:-1]
                else:
                    options[k] = v[1:]

        return key_class(b64decode(data64), comment, options=options)

    @classmethod
    def from_pubkey_file(cls, file):
        if hasattr(file, 'read'):
            return cls.from_pubkey_line(file.read())

        return cls.from_pubkey_line(open(file).read())

    def to_pubkey_line(self):
        fields = [self.type, b64encode(self.data).decode('ascii')]

        if self.options:
            buf = [k if v is True else '{}="{}"'.format(k, v)
                   for k, v in self.options.items()]
            fields.insert(0, ','.join(buf))

        if self.comment is not None:
            fields.append(self.comment)

        return ' '.join(fields)


class RSAKey(Key):
    @property
    def length(self):
        prefix, exp, n = [p for p in iter_prefixed(self.data)]

        l = (len(n)-1) * 8

        # the first bit is the sign and should always be 0
        # all bits below the highest non-0 bit are part of the modulus
        tmp = byte2int(n)
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
        if not curve.startswith(b'nistp'):
            raise NotImplementedError('Cannot determine length of curve')
        return int(curve[5:])
