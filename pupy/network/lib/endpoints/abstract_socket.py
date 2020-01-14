# -*- coding: utf-8 -*-

from socket import SHUT_RDWR
from socket import AF_UNSPEC, SOCK_STREAM
from socket import error as socket_error
from socket import timeout as socket_timeout
from select import select
from errno import EINTR

from .abstract import AbstractEndpoint, AbstractServer

from .. import getLogger


logger = getLogger('epsocket')


class AbstractSocket(AbstractEndpoint):
    MAX_IO_CHUNK = 65536

    __slots__ = (
        '_fileno',
    )

    def __init__(self, handle):
        self._fileno = handle.fileno()
        super(AbstractSocket, self).__init__(
            handle, handle.getpeername()
        )

    def _read_impl(self, timeout):
        to_read = None
        to_close = None
        data = None

        while True:
            try:
                to_read, _, to_close = select(
                    (self._handle,), (), (self._handle,), timeout
                )

                if to_read:
                    data = self._handle.recv(self.MAX_IO_CHUNK)
                    if not data:
                        data = None
                        to_close = 'stream closed'

            except socket_timeout:
                pass

            except socket_error as e:
                if e.args[0] == EINTR:
                    continue

                to_close = str(e)

            break

        if to_close:
            self.close()

            if not data:
                raise EOFError(
                    '{} closed - {}'.format(self, to_close))

        if __debug__:
            logger.debug('%s: recv=%s', self, len(data) if data else 'NONE')

        return data

    def _write_impl(self, data):
        sent = 0
        to_close = False

        while True:
            try:
                sent = self._handle.send(data)
                if not sent:
                    to_close = 'EOF'

            except socket_timeout:
                return 0

            except socket_error as e:
                if e.args[0] == EINTR:
                    continue

                to_close = str(e)

            break

        if to_close:
            self.close()

            if not data:
                raise EOFError('{} closed - {}', self, to_close)

        return sent

    def _close_impl(self):
        try:
            self._handle.shutdown(SHUT_RDWR)
        except (OSError, socket_error):
            pass

        try:
            self._handle.close()
        except (OSError, socket_error) as e:
            if __debug__:
                logger.exception('%s - close error - %s', e)

    def __repr__(self):
        return 'Fd({}{})'.format(
            self._fileno, '' if self._handle else ' (closed)'
        )


class AbstractSocketAddress(object):
    __slots__ = (
        'address', 'family', 'socktype'
    )

    def __init__(self, address, family=AF_UNSPEC, socktype=SOCK_STREAM):
        self.address = address
        self.family = family
        self.socktype = socktype

    def __repr__(self):
        return '{}({})'.format(
            self.__class__.__name__, ', '.join(
                '{}={}'.format(
                    slot, getattr(self, slot)
                ) for slot in self.__slots__
            )
        )


class AbstractSocketServer(AbstractServer):
    POLL_TIMEOUT = 1000
    MAX_QUEUED_CONNECTIONS = 32

    __slots__ = (
        '_sockets',
    )

    def __init__(self, uris, pupy_srv, transport_class, transport_kwargs={}):
        super(AbstractSocketServer, self).__init__(
            uris, pupy_srv, transport_class,
                transport_kwargs=transport_kwargs)

        self._sockets = []

    def _impl_listen(self):
        for socket in self._sockets:
            socket.listen(self.MAX_QUEUED_CONNECTIONS)

    def _impl_accept(self):
        ready, _, failed = select(
            self._sockets, [], self._sockets, self.POLL_TIMEOUT)

        for socket in failed:
            if socket in self._sockets:
                self._sockets.remove(socket)
                logger.error('%s._imp_accept():socket=%s failed', self, socket)

        if not self._sockets:
            raise EOFError('No open sockets')

        return tuple(socket.accept() for socket in ready if socket not in failed)

    def _impl_close(self):
        while True:
            try:
                socket = self._sockets.pop()
                try:
                    socket.close()
                except OSError:
                    pass

            except IndexError:
                break
