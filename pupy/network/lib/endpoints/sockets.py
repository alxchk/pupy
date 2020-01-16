# -*- coding: utf-8 -*-

__all__ = ('register',)

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

from urlparse import urlparse, ParseResult

from netaddr import IPAddress, AddrFormatError

from .abstract_socket import (
    AbstractSocket, AbstractSocketServer
)

from network.lib import getLogger
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


def register(schemas):
    schemas.update({
        'tcp': (endpoint_from_uri_tcp, server_from_uri_tcp),
        'udp': (endpoint_from_uri_udp, server_from_uri_udp),
        'ssl': (endpoint_from_uri_tls, server_from_uri_tls)
    })


class TcpSocket(AbstractSocket):
    DEFAULT_TIMEOUT = 30
    SUPPORTED_PROXIES = ('SOCKS5', 'HTTP')


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

    def _impl_resolve(self, uris):
        pairs = []
        results = []

        for uri in uris:
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


def endpoint_from_uri_tcp(credentials, uri, *args, **kwargs):
    return endpoint_from_uri_any(
        SOCK_STREAM, uri, *args, **kwargs
    )


def endpoint_from_uri_udp(credentials, uri, *args, **kwargs):
    return endpoint_from_uri_any(
        SOCK_DGRAM, uri, *args, **kwargs
    )


def endpoint_from_uri_tls(credentials, uri, *args, **kwargs):
    sock = endpoint_from_uri_any(credentials, 
        uri, *args, **kwargs
    )
    return wrap_tls(credentials, False, sock, uri, *args, **kwargs)


def endpoint_from_uri_any(required_socktype, uri, *args, **kwargs):

    logger.debug(
        'endpoint_from_uri_any(%s, %s, %s, %s)',
        required_socktype, uri, args, kwargs
    )

    lan_proxies = kwargs.get('lan_proxies', None)
    wan_proxies = kwargs.get('wan_proxies', None)

    timeout = kwargs.get('timeout', TcpSocket.DEFAULT_TIMEOUT)
    rdns = kwargs.get('rdns', True)

    if proxies:
        sock = _connect_proxies(
            proxies, uri, required_socktype, timeout, rdns
        )
    else:
        sock = _connect_direct(uri, required_socktype, timeout)

    sock.setsockopt(SOL_SOCKET, SO_KEEPALIVE, 1)

    if all((TCP_KEEPIDLE, TCP_KEEPINTVL, TCP_KEEPCNT)):
        sock.setsockopt(IPPROTO_TCP, TCP_KEEPIDLE, 1 * 60)
        sock.setsockopt(IPPROTO_TCP, TCP_KEEPINTVL, 5 * 60)
        sock.setsockopt(IPPROTO_TCP, TCP_KEEPCNT, 10)

    elif SIO_KEEPALIVE_VALS and hasattr(sock, 'ioctl'):
        sock.ioctl(SIO_KEEPALIVE_VALS, (1, 1*60*1000, 5*60*1000))

    if kwargs.get('nonblocking', False):
        sock.setblocking(0)

    return AbstractSocket(sock)


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


def _connect_direct(uri, required_socktype, timeout):
    logger.debug(
        'Connect direct to %s (socktype=%d)', uri, required_socktype
    )

    sock = None
    propositions = getaddrinfo(
        uri.hostname, uri.port, AF_UNSPEC, required_socktype
    )
    count = len(propositions)

    for idx, (family, socktype, proto, _, addr) in enumerate(propositions):
        sock = socket(family, socktype, proto)
        sock.settimeout(timeout)

        try:
            sock.connect(addr)
            return sock
        except socket_error:
            if idx + 1 == count:
                raise


def _connect_proxies(proxies, uri, required_socktype, timeout, rdns):
    if not rdns:
        try:
            propositions = getaddrinfo(
                uri.hostname, uri.port, AF_UNSPEC, required_socktype
            )

            count = len(propositions)

            for idx, (family, socktype, proto, _, addr) in enumerate(
                    propositions):
                
                resolved_uri = ParseResult(
                    uri[0], '{}:{}'.format(*addr), *uri[2:]
                )

                try:
                    return _connect_proxies_one(
                        proxies, resolved_uri, family, socktype, proto,
                        timeout
                    )
                except socket_error:
                    if idx + 1 == count:
                        raise

        except gaierror:
            # Fallback to rdns
            return _connect_proxies(
                proxies, uri, required_socktype, timeout, True)

    family = AF_INET

    try:
        ip_address = IPAddress(uri.hostname)
        if ip_address.version == 6:
            family = AF_INET6
    except AddrFormatError:
        pass        

    return _connect_proxies_one(
        proxies, uri, family, required_socktype, 0, timeout
    )


def _connect_proxies_one(
        proxies, uri, family, socktype, proto, timeout):

    sock = socksocket(family, socktype, proto)

    host = uri.hostname
    port = int(uri.port or 443)

    logger.debug(
        'Connect to: %s:%d timeout=%d via proxies',
        host, port, timeout)

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

    sock.settimeout(timeout)
    sock.connect((host, port))

    logger.debug(
        'Connected to: %s:%d: %s', host, port, sock)

    return sock


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
