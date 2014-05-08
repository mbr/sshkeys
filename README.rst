sshkeys
=======

.. image:: https://travis-ci.org/mbr/sshkeys.svg?branch=master
   :target: https://travis-ci.org/mbr/sshkeys

``sshkeys`` is a small library for reading SSH public keys, extracting some
information from them and possibly outputting them again. It's mainly useful
when dealing with scripts that manipulate ``~/.ssh/authorized_keys`` or handle
user's public keys in other ways.

sshkeys supports Python 2.6, 2.7, 3.3, 3.4.

Example
=======

Here's a small example session::

    >>> from sshkeys import Key
    >>> k = Key.from_pubkey_file('sample_rsa.key.pub')
    >>> print k.readable_fingerprint
    b9:e2:58:1a:74:fc:62:13:52:ad:f7:28:0b:09:91:54
    >>> print k.comment
    sample_rsa_key@host
    >>> k.comment = 'command="nothing",no-x11-forwarding'
    >>> print k.to_pubkey_line()
    ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDDN2n2kt99/aYpPbOZRJeGVyFs74R1/QCqN351cuXLGK93lalDyIuIiUvMEYezregae1xDWXtCD+q9HMQpfl62R2R1h3b8CMX8fpcGGXHJAxFWg/Sz8qXcbOeTRKdnBIWlUrkDi/7hWKZdXLsiSPJeX9wmLhA5HCdHye1yFlGxSixTVK2fXyS9ZFEbBcIL8Aiq2EMQktCy2gDOiJArpCF7pvsGqiLUxdCpOT+wuL+oGV47yVveGt9TcesnmZ1HxESXAIS22Vo2MnTABxdNxNrs1ih3+4wdJ+gpoLo0lRNdjARRlcoH/fJvrXdbOrf//ARzuR9JKfyKz+9aUEPxGtlEStbVysTjY2M3+Z4msbxh4x3ezpujhzpFCeLDHcAPg/HS6GoO7zGcdJ8knCZK5ujOvFku03Es+jLrGNjACDOlLSYf9RHPqHvo/Fn+lCLJWZoc0qiuICuHbEDU0fJ4qbVovZtdQtTwzQ8Az+VsLhJfehhadvb5hOCw3o4i9j1dJzcNfKJiBhab25GdfEYE097fDoYu/M0mi14AHWR0KI9o9Fd526x9B6c6gfljbHJZcMGXhzfyO6nIsbZK6teJR7qh/8EQ7shOyfdcJkexvsbeNm12VTW34ar+FjrApgN1QtY1+/6SDNSeOQqnBu2qENQVllSCfxOholMnVpO5ly1G2Q== command="nothing",no-x11-forwarding
