import binascii
from base64 import b64decode, b64encode
from collections import OrderedDict
from hashlib import md5
from struct import unpack

from six import byte2int

__version__ = '0.5'


def iter_prefixed(data):
    while data:
        # get next prefix
        l = unpack('!I', data[:4])[0]
        packet, data = data[4:4 + l], data[4 + l:]
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
        h = binascii.hexlify(self.fingerprint).decode()
        return ':'.join(h[i:i + 2] for i in range(0, len(h), 2))

    @staticmethod
    def _extract_options(line):
        r'''Given a line as it would appear in the authorized_keys file,
        return an OrderedDict of options, and the remainder of a line as a
        string.

        >>> Key._extract_options(r'no-pty,command="sh" ssh-rsa AAAAB3NzaC1yc2EAAA...OFy5Lwc8Lo+Jk=')
        (OrderedDict([('no-pty', True), ('command', 'sh')]), 'ssh-rsa AAAAB3NzaC1yc2EAAA...OFy5Lwc8Lo+Jk=')
        >>> Key._extract_options(r'ssh-rsa AAAAB3NzaC1yc...Lwc8OFy5Lo+kU=')
        (OrderedDict(), 'ssh-rsa AAAAB3NzaC1yc...Lwc8OFy5Lo+kU=')
        '''
        options = OrderedDict({})
        quoted = False
        escaped = False
        option_name = ''
        option_val = None
        key_without_options = ''
        in_options = True
        in_option_name = True
        for letter in line.strip():
            if in_options:
                if quoted:
                    if letter == "\\":
                        escaped = True
                    elif letter == '"':
                        if escaped:
                            option_val += letter
                            escaped = False
                        else:
                            quoted = False
                    else:
                        if escaped:
                            option_val += "\\"
                            escaped = False
                        option_val += letter
                else:  # not quoted
                    if letter == ' ':
                        # end of options
                        in_options = False
                        if (option_name in ['ssh-rsa', 'ssh-dss'] or
                            option_name.startswith('ecdsa-')):
                            # what we thought was an option name was really the
                            # key type, and there are no options
                            key_without_options = option_name + " "
                            option_name = ''
                        else:
                            if option_val is None:
                                options[option_name] = True
                            else:
                                options[option_name] = option_val
                    elif letter == '"':
                        quoted = True
                    elif letter == '=':
                        # '=' separated option name from value
                        in_option_name = False
                        if option_val is None:
                            option_val = ''
                    elif letter == ',':
                        # next option_name
                        if option_val is None:
                            options[option_name] = True
                        else:
                            options[option_name] = option_val
                        in_option_name = True
                        option_name = ''
                        option_val = None
                    else:  # general unquoted letter
                        if in_option_name:
                            option_name += letter
                        else:
                            option_val += letter
            else:
                key_without_options += letter
        if key_without_options == '':
            # certain mal-formed keys (e.g. a line not containing any spaces)
            # will be completely swallowed up by the above parser. It's
            # better to follow the principle of least surprize and return the
            # original line, allowing the error to be handled later.
            return OrderedDict({}), line.strip()
        else:
            return options, key_without_options

    @classmethod
    def from_pubkey_line(cls, line):
        """Generate Key instance from a a string. Raise ValueError if string is
        malformed"""
        options, key_without_options = cls._extract_options(line)
        if key_without_options == '':
            raise ValueError("Empty key")
        # the key (with options stripped out) should consist of the fields
        # "type", "data", and optionally "comment", separated by a space.
        # The comment field may contain additional spaces
        fields = key_without_options.strip().split(None, 2)  # maxsplit=2
        if len(fields) == 3:
            type_str, data64, comment = fields
        elif len(fields) == 2:
            type_str, data64 = fields
            comment = None
        else:  # len(fields) <= 1
            raise ValueError("Key has insufficient number of fields")

        try:
            data = b64decode(data64)
        except (binascii.Error, TypeError):
            raise ValueError("Key contains invalid data")

        key_type = next(iter_prefixed(data))

        if key_type == b'ssh-rsa':
            key_class = RSAKey
        elif key_type == b'ssh-dss':
            key_class = DSAKey
        elif key_type.startswith(b'ecdsa-'):
            key_class = ECDSAKey
        else:
            raise ValueError('Unknown key type {}'.format(key_type))

        return key_class(b64decode(data64), comment, options=options)

    @classmethod
    def from_pubkey_file(cls, file):
        """Generate a Key instance from a file. Raise ValueError is key is
        malformed"""
        if hasattr(file, 'read'):
            return cls.from_pubkey_line(file.read())

        return cls.from_pubkey_line(open(file).read())

    def to_pubkey_line(self):
        fields = [self.type, b64encode(self.data).decode('ascii')]

        if self.options:
            buf = []
            for k, v in self.options.items():
                if v is True:  # NOT the same as 'if v:'!
                    buf.append(k)
                else:
                    buf.append('%s="%s"' % (k, v.replace('"', r'\"')))
            fields.insert(0, ','.join(buf))

        if self.comment is not None:
            fields.append(self.comment)

        return ' '.join(fields)


class RSAKey(Key):
    @property
    def length(self):
        prefix, exp, n = [p for p in iter_prefixed(self.data)]

        l = (len(n) - 1) * 8

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
