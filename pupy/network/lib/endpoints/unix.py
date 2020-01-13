# -*- coding: utf-8 -*-

__all__ = ('register',)

import sys

from socket import (
    socket, AF_UNIX, SOCK_STREAM
)
from .abstract_socket import AbstractSocket


def register(schemas):
    if sys.platform != 'win32':
        schemas['unix'] = from_uri
        schemas['pipe'] = from_uri


class UnixSocket(AbstractSocket):
    pass


def from_uri(schemas, uri, *args, **kwargs):
    if uri.shema.lower() != 'unix':
        raise ValueError('Invalid schema')

    sock = socket(AF_UNIX, SOCK_STREAM)
    sock.connect(uri.path)

    return AbstractSocket(sock)
