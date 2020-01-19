# -*- coding: utf-8 -*-

__endpoints__ = (
    'InetSocketClient',  'InetSocketServer'
)

from os import write, close, unlink

from socket import (
    socket, getaddrinfo, gaierror,
    AF_INET, AF_INET6, AF_UNSPEC,
    SOCK_DGRAM, SOCK_STREAM,
    IPPROTO_TCP
)

from ssl import (
    SSLContext, SSLError, wrap_socket,
    CERT_REQUIRED, CERT_NONE, PROTOCOL_TLSv1_2
)

from socket import error as socket_error
from tempfile import NamedTemporaryFile

from urlparse import ParseResult

from netaddr import IPAddress, AddrFormatError

from .abstract import (
    Keywords, Schemes
)

from .abstract_socket import (
    AbstractSocket, AbstractSocketServer, EndpointCapabilities,
)

from network.lib import getLogger
from network.lib.proxies import find_proxies_for_uri, ProxyHints
from network.lib.socks import socksocket, ProxyError

from socket import SOL_SOCKET, SO_KEEPALIVE

try:
    from socket import (
        TCP_KEEPIDLE, TCP_KEEPINTVL, TCP_KEEPCNT
    )
except ImportError:
    TCP_KEEPIDLE = None
    TCP_KEEPINTVL = None
    TCP_KEEPCNT = None

try:
    from socket import SIO_KEEPALIVE_VALS
except ImportError:
    SIO_KEEPALIVE_VALS = None

logger = getLogger('tcp')


def _get_address_family(address):
    family = AF_UNSPEC

    try:
        ip_address = IPAddress(address)
        if ip_address.version == 6:
            family = AF_INET6
        else:
            family = AF_INET
    except AddrFormatError:
        pass

    return family


def _enable_keepalive(sock):
    sock.setsockopt(SOL_SOCKET, SO_KEEPALIVE, 1)

    if all((TCP_KEEPIDLE, TCP_KEEPINTVL, TCP_KEEPINTVL)):
        sock.setsockopt(IPPROTO_TCP, TCP_KEEPIDLE, 1 * 60)
        sock.setsockopt(IPPROTO_TCP, TCP_KEEPINTVL, 5 * 60)
        sock.setsockopt(IPPROTO_TCP, TCP_KEEPINTVL, 10)
    elif all((SIO_KEEPALIVE_VALS, hasattr(sock, 'ioctl'))):
        sock.ioctl(SIO_KEEPALIVE_VALS, (1, 1*60*1000, 5*60*1000))


class InetSocketClient(AbstractSocket):
    __slots__ = (
        'proxy_hints', 'family', 'socktype', 'proto', 'timeout'
    )

    SCHEMES = Schemes(
        ('tcp', 'TCP over IPv4/IPv6 client'),
        ('udp', 'UDP over IPv4/IPv6 client'),
    )

    @classmethod
    def keywords(cls):
        keywords = Keywords(
            ('timeout', 'Connection timeout (sec)', int, 10),
            ('try_proxy', 'Attempt to connect via proxies', bool, True),
            ('lan_proxies', 'Proxies to pass to the Internet from the LAN', str, None),
            ('wan_proxies', 'Proxies to pass from the Internet to the pupysh', str, None),
            ('use_wpad', 'Try to autodetect proxy using WPAD', bool, True),
            ('auto_proxies', 'Try to autodetect proxies from environment', bool, True),
            ('try_direct', 'Try to direct connection if proxy failed', bool, True)
        )

        keywords += super(InetSocketClient, cls).keywords()
        return keywords

    def __init__(
        self, uri, handle=None, name=None, capabilities=None,
            timeout=10, try_proxy=True, lan_proxies=None, wan_proxies=None,
            use_wpad=True, auto_proxies=True, try_direct=True,proxy_native_implementation=[]):

        self.uri = uri
        self.proxy_hints = None
        if try_proxy:
            self.proxy_hints = ProxyHints(
                proxy_native_implementation, lan_proxies,
                wan_proxies, auto_proxies, use_wpad, try_direct
            )

        self.timeout = timeout

        if not (self.uri.hostname and self.uri.port):
            raise ValueError('Both host and port must be specified')

        if handle:
            self.family = handle.family
            self.socktype = handle.type
            self.proto = handle.proto

            if name is None:
                name = handle.getpeername()
        else:
            self.family = _get_address_family(uri.hostname)

            if uri.scheme.lower() == 'udp':
                self.socktype = SOCK_DGRAM
            else:
                self.socktype = SOCK_STREAM

            self.proto = 0

        if capabilities is None:
            capabilities = EndpointCapabilities(
                max_io_chunk=32768 if self.socktype == SOCK_STREAM else 1200
            )

        super(InetSocketClient, self).__init__(
            uri, capabilities, handle, name
        )

    def _create_handle_impl(self, *args, **kwargs):
        proxy_hints = kwargs.get('proxy_hints', None)

        if proxy_hints is None:
            proxy_hints = self.proxy_hints

        if proxy_hints:
            if proxy_hints is True:
                proxy_hints = None

            try:
                return self._create_handle_via_proxy_impl(proxy_hints)
            except EOFError:
                if not proxy_hints or proxy_hints.try_direct:
                    return self._create_handle_direct_impl()
                else:
                    raise
        else:
            return self._create_handle_direct_impl()

    def _create_handle_via_proxy_impl(self, proxy_hints):
        for proxies in find_proxies_for_uri(self.uri, proxy_hints):
            try:
                return self._create_handle_via_proxy_attempt_impl(proxies)
            except (ProxyError, socket_error) as e:
                logger.info(
                    'Failed to connect via proxies (%s): %s', proxies, e
                )

        raise EOFError('No connectable proxies found')

    def _resolve_uri(self):
        propositions = getaddrinfo(
            self.uri.hostname, self.uri.port, AF_UNSPEC, self.socktype
        )

        for family, socktype, proto, _, addr in propositions:
            yield family, socktype, proto, addr

    def _create_handle_via_proxy_attempt_impl(self, proxies):

        sock = socksocket(self.family, self.socktype, self.proto)

        host = self.uri.hostname
        port = int(self.uri.port or 443)

        logger.debug(
            'Connect to: %s:%d timeout=%d via proxies',
            host, port, self.timeout
        )

        for proxy in proxies:
            proxy_addr = proxy.addr
            proxy_port = None

            if ':' in proxy_addr:
                proxy_addr, proxy_port = proxy_addr.rsplit(':', 1)
                proxy_port = int(proxy_port)

            logger.debug(
                'Connect via %s:%s (type=%s%s)',
                proxy_addr, proxy_port or 'default', proxy.type,
                ' auth={}:{}'.format(
                    proxy.username, proxy.password
                ) if proxy.username else '')

            sock.add_proxy(
                proxy_type=proxy.type,
                addr=proxy_addr,
                port=proxy_port,
                rdns=True,
                username=proxy.username,
                password=proxy.password
            )

        sock.settimeout(self.timeout)
        sock.connect((host, port))

        logger.debug(
            'Connected to: %s:%d: %s', host, port, sock)

        return sock, '{}:{}'.format(host, port)

    def _create_handle_direct_impl(self):
        propositions = getaddrinfo(
            self.uri.hostname, self.uri.port, AF_UNSPEC, self.socktype
        )

        lcnt = len(propositions)

        sock = None

        for idx, (family, socktype, proto, _, addr) in enumerate(propositions):
            try:
                sock = socket(family, socktype, proto)
                sock.connect(addr)

            except socket_error:
                if idx + 1 == lcnt:
                    raise

        _enable_keepalive(sock)

        return sock, '{}:{}'.format(*addr)


class InetSocketServer(AbstractSocketServer):
    DEFAULT_PORT = 443

    __slots__ = (
        'family', 'sockproto'
    )

    def __init__(
        self, uris, pupy_srv,
            family=AF_UNSPEC, sockproto=SOCK_STREAM):

        super(InetSocketServer, self).__init__(uris, pupy_srv)

        self.family = family
        self.sockproto = sockproto

    def _impl_resolve(self):
        pairs = []
        results = []

        for uri in self.uris:
            port = uri.port or self.DEFAULT_PORT
            if not uri.hostname:
                for any_addr in ('0.0.0.0', '::'):
                    pairs.append((uri, any_addr, port, True))
            else:
                pairs.append((uri, uri.hostname, port, False))

        for uri, host, port, may_fail in pairs:
            try:
                propositions = getaddrinfo(
                    host, port, self.family, self.sockproto
                )

                for family, socktype, proto, _, addr in propositions:
                    results.append((
                        uri,
                        (family, socktype, proto, addr)
                    ))

            except gaierror as e:
                logger.info(
                    '%s: Failed to resolve %s:%s: %s', self, host, port, addr, e
                )

                if not may_fail:
                    raise

        return results

    def _impl_bind(self, addresses):
        sockets = {}

        try:
            for uri, (family, socktype, proto, addr) in addresses:
                sock = socket(family, socktype, proto)
                sock.bind(addr)

                sockets[sock] = uri
        except Exception as e:
            logger.error('%s: Failed to bind %s: %s', self, addr, e)

            for sock in sockets:
                sock.close()

            raise

        self._sockets = sockets


class TlsSocketServer(InetSocketServer):
    __slots__ = (
        'hostname', 'ssl_auth', 'ssl_protocol', 'ssl_ciphers',
        'credentials'
    )

    def __init__(
        self, credentials, uris, pupy_srv, family=AF_UNSPEC,
            ssl_auth=False, ssl_protocol=None, ssl_ciphers=None,
            hostname=None):

        super(TlsSocketServer, self).__init__(uris, pupy_srv, family)
        self.credentials = credentials
        self.ssl_auth = ssl_auth
        self.ssl_protocol = ssl_protocol
        self.ssl_ciphers = ssl_ciphers
        self.hostname = hostname
        self.credentials = credentials

    def _impl_accept(self):
        result = []

        for (sock, serversock) in super(TlsSocketServer, self)._impl_accept():
            try:
                result.append(
                    wrap_tls(
                        self.credentials,
                        True, sock,
                        self._listener_uri_by_serversock(serversock),
                        ssl_auth=self.ssl_auth,
                        ssl_protocol=self.ssl_protocol,
                        ssl_ciphers=self.ssl_ciphers,
                        hostname=self.hostname,
                    )
                )
            except SSLError as e:
                logger.error(
                    'SSL error during accept (%s): %s', serversock, e
                )

        return result


class TcpSocketServer(AbstractSocketServer):
    pass


def wrap_tls(credentials, server_side, sock, uri, *args, **kwargs):
    ssl_auth = kwargs.get('ssl_auth', True)
    ssl_protocol = kwargs.get('ssl_protocol', PROTOCOL_TLSv1_2)
    ssl_ciphers = kwargs.get(
        'ssl_ciphers', 'HIGH:!aNULL:!MD5:!RC4:!3DES:!DES')

    hostname = kwargs.get('hostname', uri.hostname)

    if not ssl_auth:
        ctx = SSLContext(ssl_protocol)
        ctx.verify_mode = CERT_NONE
        ctx.check_hostname = False
        ctx.set_ciphers(ssl_ciphers)

        return ctx.wrap_socket(
            sock, server_hostname=hostname,
            server_side=server_side
        )

    is_server = kwargs.get('server', False)

    cert = credentials['SSL_CLIENT_CERT']
    key = credentials['SSL_CLIENT_KEY']
    ca = credentials['SSL_CA_CERT']
    role = credentials.get(
        'role', 'CONTROL' if is_server else 'CLIENT'
    )

    with NamedTemporaryFile() as cert_file:
        with NamedTemporaryFile() as key_file:
            with NamedTemporaryFile() as ca_file:

                try:
                    cert_file.write(cert)
                    cert_file.flush()

                    key_file.write(key)
                    key_file.flush()

                    ca_file.write(ca)
                    ca_file.flush()

                except OSError as e:
                    logger.error(
                        'Error writing certificates to temp file %s', e)
                    raise

                wrapped_socket = wrap_socket(
                    socket,
                    certfile=cert_file.name,
                    keyfile=key_file.name,
                    ca_certs=ca_file.name,
                    server_side=server_side,
                    cert_reqs=CERT_REQUIRED,
                    ssl_version=ssl_protocol,
                    ciphers=ssl_ciphers
                )

    peer = wrapped_socket.getpeercert()

    peer_role = ''

    for (item) in peer['subject']:
        if item[0][0] == 'organizationalUnitName':
            peer_role = item[0][1]

    if not (role == 'CLIENT' and peer_role == 'CONTROL' or \
        role == 'CONTROL' and peer_role == 'CLIENT'):
        raise ValueError('Invalid peer role: {}'.format(peer_role))

    return wrapped_socket


def server_from_uri_tls(credentials, uri, *args, **kwargs):
    return TlsSocketServer(
        credentials,
        uri,
        kwargs.get('pupy_srv'),
        ssl_auth=kwargs.get('ssl_auth', True),
        ssl_protocol=kwargs.get('ssl_protocol', PROTOCOL_TLSv1_2),
        ssl_ciphers=kwargs.get(
            'ssl_ciphers', 'HIGH:!aNULL:!MD5:!RC4:!3DES:!DES'
        )
    )


def server_from_uri_tcp(credentials, sockproto, uri, *args, **kwargs):
    return InetSocketServer(
        uri, kwargs.get('pupy_srv'),
        kwargs.get('family'), SOCK_STREAM
    )


def server_from_uri_udp(credentials, sockproto, uri, *args, **kwargs):
    return InetSocketServer(
        uri, kwargs.get('pupy_srv'),
        kwargs.get('family'), SOCK_DGRAM
    )
