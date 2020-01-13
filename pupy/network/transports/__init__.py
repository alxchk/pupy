# -*- coding: utf-8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root
# of the project for the detailed licence terms

__all__ = (
    'Transport',
    'LAUNCHER_TYPE_ALL',
    'LAUNCHER_TYPE_BIND', 'LAUNCHER_TYPE_CONNECT', 'LAUNCHER_TYPE_DNSCNC'
)

class TransportException(Exception):
    pass


LAUNCHER_TYPE_ALL = 0
LAUNCHER_TYPE_CONNECT = 1
LAUNCHER_TYPE_BIND = 2
LAUNCHER_TYPE_DNSCNC = 3


class Transport(object):
    info='no description available'
    server=None
    client=None
    client_kwargs={}
    authenticator=None
    stream=None
    client_transport=None
    server_transport=None
    dependencies=[] # dependencies needed when generating payloads
    credentials=[] # list of credentials to embbed during payload generation
    name=None
    launcher_type=LAUNCHER_TYPE_ALL
    dgram=False
    internal_proxy_impl = []

    def __init__(self, bind_payload=False):
        super(Transport, self).__init__()
        self.bind_payload=bind_payload
        if self.bind_payload:
            self.launcher_type=LAUNCHER_TYPE_BIND
        self.client_transport_kwargs={}
        self.server_transport_kwargs={}

    def parse_args(self, args):
        ''' parse arguments and raise an error if there is missing/incorrect arguments '''
        self.client_transport_kwargs.update(args)
        self.server_transport_kwargs.update(args)
