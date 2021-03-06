#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os

from setuptools import setup, find_packages


def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()


setup(
    name='sshkeys',
    version='0.6.dev1',
    description='A library for working with public SSH keys.',
    long_description=read('README.rst'),
    author='Marc Brinkmann',
    author_email='git@marcbrinkmann.de',
    url='http://github.com/mbr/sshkeys',
    license='MIT',
    packages=find_packages(exclude=['tests']),
    install_requires=['six'],
)
