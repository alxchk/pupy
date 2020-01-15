# -*- coding: utf-8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root
# of the project for the detailed licence terms

__all__ = (
    'load_network_modules', 'transports', 'launchers',
    'from_uri'
)


import logging

from urlparse import urlparse, ParseResult

from pkgutil import iter_modules
from importlib import import_module

from network import transports as transports_conf
from network.lib import endpoints as endpoints_lib
from network.lib import transports as transports_lib

from network.lib.base import TransportWrapper

transports = {}

launchers = {}
endpoints = {}
transports_ng = {}


def add_transport(module_name):
    try:
        confmodule = import_module(
            'network.transports.{}.conf'.format(module_name))

        if not confmodule:
            logging.warning('Import failed: %s', module_name)
            return

        if not hasattr(confmodule, 'TransportConf'):
            logging.warning('TransportConf is not present in %s', module_name)
            return

        t = confmodule.TransportConf
        if t.name is None:
            t.name = module_name

        transports[t.name] = t
        logging.debug('Transport loaded: %s', t.name)

    except Exception, e:
        logging.exception('Transport disabled: %s: %s', module_name, e)


def load_launchers():
    try:
        from .lib.launchers.connect import ConnectLauncher
        launchers['connect'] = ConnectLauncher
    except Exception, e:
        logging.exception('%s: ConnectLauncher disabled', e)

    try:
        from .lib.launchers.auto_proxy import AutoProxyLauncher
        launchers['auto_proxy'] = AutoProxyLauncher
    except Exception, e:
        logging.exception('%s: AutoProxyLauncher disabled', e)

    try:
        from .lib.launchers.bind import BindLauncher
        launchers['bind'] = BindLauncher
    except Exception, e:
        logging.exception('%s: BindLauncher disabled', e)

    try:
        from .lib.launchers.dnscnc import DNSCncLauncher
        launchers.update({
            'dnscnc': DNSCncLauncher
        })

    except Exception as e:
        logging.exception('%s: DNSCncLauncher disabled', e)
        DNSCncLauncher = None


def load_legacy_configurations():
    for _, module_name, _ in iter_modules(transports_conf.__path__):
        add_transport(module_name)


def load_network_endpoints():
    for _, module_name, _ in iter_modules(endpoints_lib.__path__):
        try:
            module = import_module(__name__ + '.' + module_name)
        except ImportError as e:
            logging.exception(
                'Import failed for %s.%s: %s',
                __name__, module_name, e)
            continue

        if hasattr(module, 'register'):
            module.register(endpoints)


def load_transports():
    for _, module_name, _ in iter_modules(endpoints_lib.__path__):
        try:
            module = import_module(__name__ + '.' + module_name)
        except ImportError as e:
            logging.exception(
                'Import failed for %s.%s: %s',
                __name__, module_name, e)
            continue

        if hasattr(module, 'register'):
            logging.debug('Register module %s', module_name)
            module.register(transports_ng)


def load_network_modules():
    logging.debug("Load legacy configurations ..")
    load_legacy_configurations()

    logging.debug("Load network endpoints ..")
    load_network_endpoints()

    logging.debug("Load transports ..")
    load_transports()

    logging.debug("Load launchers ..")
    load_launchers()


def transports_conf_from_uri(uri, bind=False):
    if '+' not in uri.scheme:
        return None, []
    
    parts = uri.scheme.split('+')
    required_transports = parts[1:]

    chained_credentials = set()
    transports = []

    for required_transport in required_transports:
        transports_configuration = transports_ng.get(required_transport)
        if not transports_configuration:
            raise ValueError('Unregistered transport {}'.format(
                transports_configuration))

        client_transport, server_transport = transports_configuration
        transport = server_transport if bind else client_transport

        chained_credentials.update(transport.credentials)
        transports.append(transport)

    if len(transports) > 1:
        class ChainedTransports(TransportWrapper):
            name = '+'.join(required_transports)
            credentials = tuple(chained_credentials)
            cls_chain = transports
    
        transport = ChainedTransports
    else:
        transport = transports[0]

    return transport


def from_uri(uri, bind=False, args=[], kwargs={}, credentials={}):
    if not isinstance(uri, ParseResult):
        uri = urlparse(uri)

    # At endpoint level we are interested only at first level
    # tcp+obfs3+rsa:// -> tcp://

    entity = None
    transport = None

    required_credentials = []

    if '+' in uri.scheme:
        transport, required_credentials = transports_conf_from_uri(
            uri, bind)

        parts = uri.scheme.split('+')
        scheme = parts[0]
        uri = ParseResult(scheme, uri[1:])
    
    credential_data = {
        credential:credentials[credential]
        for credential in required_credentials
    }

    ep_configuration = endpoints.get(uri.scheme.lower())
    if not ep_configuration:
        raise ValueError('Unregistered scheme {}'.format(
            repr(uri.scheme.lower())))
    
    client_ep, server_ep = ep_configuration
    ep_handler = server_ep if bind else client_ep

    entity = ep_handler(credential_data, args, kwargs)
    entity.set_transport(transport)

    return entity
