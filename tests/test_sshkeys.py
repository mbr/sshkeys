from binascii import unhexlify
import os

from sshkeys import Key

import pytest

base_path = os.path.abspath(os.path.dirname(__file__))


def _bin_fp(s):
    return unhexlify(s.replace(':', ''))


KNOWN_KEYS = [
    # sample standard 4096 bit rsa key
    {'keyfile': os.path.join(base_path, 'sample_rsa.key'),
     'pubfile': os.path.join(base_path, 'sample_rsa.key.pub'),
     'length': 4096,
     'type': 'ssh-rsa',
     'comment': 'sample_rsa_key@host',
     'fingerprint': _bin_fp('b9:e2:58:1a:74:fc:62:13:52:ad:f7:28:0b:09:91:54'),
     'readable_fp': 'b9:e2:58:1a:74:fc:62:13:52:ad:f7:28:0b:09:91:54',
     },
    # 2048 bit
    {'keyfile': os.path.join(base_path, 'sample_rsa2048.key'),
     'pubfile': os.path.join(base_path, 'sample_rsa2048.key.pub'),
     'length': 2048,
     'type': 'ssh-rsa',
     'comment': 'sample_rsa2048_key@host',
     'fingerprint': _bin_fp('23:a7:24:ea:cc:df:f9:a8:cc:73:9b:83:71:bc:c8:56'),
     'readable_fp': '23:a7:24:ea:cc:df:f9:a8:cc:73:9b:83:71:bc:c8:56',
     },
    # 1024 bit
    {'keyfile': os.path.join(base_path, 'sample_rsa1024.key'),
     'pubfile': os.path.join(base_path, 'sample_rsa1024.key.pub'),
     'length': 1024,
     'type': 'ssh-rsa',
     'comment': 'sample_rsa1024_key@host',
     'fingerprint': _bin_fp('cf:3f:e9:18:60:cb:c3:28:b8:a1:21:34:02:19:ff:a3'),
     'readable_fp': 'cf:3f:e9:18:60:cb:c3:28:b8:a1:21:34:02:19:ff:a3',
     },
    # 1234 bit
    {'keyfile': os.path.join(base_path, 'sample_rsa1234.key'),
     'pubfile': os.path.join(base_path, 'sample_rsa1234.key.pub'),
     'length': 1234,
     'type': 'ssh-rsa',
     'comment': 'sample_rsa1234_key@host',
     'fingerprint': _bin_fp('99:53:07:1a:03:1e:52:c3:25:08:5d:7e:df:ee:86:37'),
     'readable_fp': '99:53:07:1a:03:1e:52:c3:25:08:5d:7e:df:ee:86:37',
     },
]


@pytest.fixture(params=KNOWN_KEYS)
def known_key(request):
    return request.param


def test_pubkey_loading_from_line(known_key):
    k = Key.from_pubkey_file(known_key['pubfile'])

    assert k.type == known_key['type']
    assert k.length == known_key['length']
    assert k.comment == known_key['comment']
    assert k.fingerprint == known_key['fingerprint']
    assert k.readable_fingerprint == known_key['readable_fp']
