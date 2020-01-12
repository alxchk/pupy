# -*- coding: utf-8 -*-

__all__ = ('register',)

from os import write, close, unlink

from socket import (
    socket, getaddrinfo,
    AF_INET, AF_UNSPEC,
    SOCK_DGRAM, SOCK_STREAM
)

from ssl import (
    SSLContext, wrap_socket,
    CERT_REQUIRED, CERT_NONE, PROTOCOL_TLS
)

from socket import error as socket_error
from tempfile import mkstemp

from .abstract_socket import AbstractSocket

from network.lib import getLogger

logger = getLogger('tcp')


def register(schemas):
    schemas['tcp'] = from_uri_tcp
    schemas['udp'] = from_uri_udp
    schemas['ssl'] = from_uri_ssl


class TcpSocket(AbstractSocket):
    DEFAULT_TIMEOUT = 30


def from_uri_tcp(uri, *args, **kwargs):
    return from_uri_any(SOCK_STREAM, uri, *args, **kwargs)


def from_uri_udp(uri, *args, **kwargs):
    return from_uri_any(SOCK_DGRAM, uri, *args, **kwargs)


def from_uri_ssl(uri, *args, **kwargs):
    sock = from_uri_tcp(uri, *args, **kwargs)
    return wrap_ssl(sock, uri, *args, **kwargs)


def _connect_direct(uri, required_socktype, timeout):
    sock = None
    propositions = getaddrinfo(
        uri.hostname, uri.port, AF_UNSPEC, required_socktype
    )
    count = len(propositions)

    for idx, (family, socktype, proto, _, addr) in enumerate(propositions):
        sock = socket.socket(family, socktype, proto)
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


def from_uri_any(required_socktype, uri, *args, **kwargs):
    if uri.shema.lower() != 'tcp':
        raise ValueError('Invalid schema')

    proxies = kwargs.get('proxies', None)
    timeout = kwargs.get('timeout', TcpSocket.DEFAULT_TIMEOUT)

    if proxies:
        sock = _connect_proxies(proxies, uri, required_socktype, timeout)
    else:
        sock = _connect_direct(uri, required_socktype, timeout)

    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

    if all(hasattr(socket, attr) for attr in (
            'TCP_KEEPIDLE', 'TCP_KEEPINTVL', 'TCP_KEEPCNT')):
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 1 * 60)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 5 * 60)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 10)

    elif hasattr(socket, 'SIO_KEEPALIVE_VALS') and hasattr(sock, 'ioctl'):
        sock.ioctl(socket.SIO_KEEPALIVE_VALS, (1, 1*60*1000, 5*60*1000))

    if kwargs.get('nonblocking', False):
        sock.setblocking(0)

    return AbstractSocket(sock)


def wrap_ssl(sock, uri, *args, **kwargs):
    ssl_auth = kwargs.get('ssl_auth', True)
    ssl_protocol = kwargs.get('ssl_protocol', PROTOCOL_TLS)
    ssl_ciphers = kwargs.get('ssl_ciphers', 'HIGH:!aNULL:!MD5:!RC4:!3DES:!DES')

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
