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
                    slot, getattr(self, slot) for slot in self.__slots__
                )
            )
        )


class AbstractSocketServer(AbstractServer):
    __slots__ = (
        'addresses', '_listeners'
    )

    def __init__(self, addresses, service,
        transport_class, transport_kwargs={}, external=None,
            igd=None):

        super(AbstractSocketServer, self).__init__(
            service, transport_class, transport_kwargs
        )

        self.addresses = addresses
        self._listeners = []

    def _impl_make_sockets(self):
        for address in self.addresses:


    def _impl_listen(self):
        pass

    def _impl_accept(self):
        pass

    def _impl_on_verified(self, connection):
        pass

    def _impl_on_exit(self, connection):
        pass

    def _impl_close(self):
        while True:
            try:
                listener = self._listeners.pop()
                try:
                    listener.close()
                except OSError:
                    pass

            except IndexError:
                break

