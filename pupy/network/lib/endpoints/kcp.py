# -*- coding: utf-8 -*-

__all__ = (
    'KCPEndpoint', 'register'
)

from kcp import KCP
from os import urandom

from socket import socket

from . import from_uri

from .abstract import AbstractEndpoint, EndpointCapabilities
from .abstract_socket import AbstractSocket


class KCPEndpoint(AbstractEndpoint):

    __slots__ = (
        '_fileno', '_sock', '_connid',
        '_new_sent', '_initialized', '_write_only'
    )

    KCP_ID = 0

    NEW = '\x00'
    DAT = '\x01'
    END = '\x02'

    UDP_HEADER_SIZE = 24 + 5

    def __init__(self, handle, interval=64, write_only=False, kcp_id=None):
        self._write_only = write_only

        if isinstance(handle, AbstractSocket):
            self._handle = handle.handle
            self._fileno = handle.name
        elif isinstance(handle, tuple) and len(handle) == 3:
            self._sock, _, handle = handle
            self._write_only = True
        elif isinstance(handle, socket):
            self._sock = handle
            handle = KCP(
                handle.fileno(),
                KCPEndpoint.KCP_ID if kcp_id is None else kcp_id,
                interval=interval
            )
        else:
            raise ValueError(
                'Unsupported handle value {}/{}'.format(
                    handle, type(handle)))

        self._fileno = self._sock.fileno()

        self._connid = urandom(4)
        self._new_sent = False
        self._initialized = False

        super(KCPEndpoint, self).__init__(
            handle,
            self._fileno,
            EndpointCapabilities(
                max_io_chunk=handle.mtu - KCPEndpoint.UDP_HEADER_SIZE
            )
        )

    @property
    def MAX_IO_CHUNK(self):
        return self._handle.mtu

    def _send_packet(self, flag, data='', need_flush=False):
        if flag in (self.NEW, self.END):
            need_flush = True

        if flag == self.DAT and not self._new_sent:
            flag = self.NEW
            self._new_sent = True

        self._handle.send(flag + self._connid + data)
        if need_flush:
            self._handle.flush()

    def _parse_packet(self, buf):
        if not buf:
            return None
        
        if len(buf) < 5:
            raise EOFError('Short datagram ({})'.format(len(buf)))

        flag = buf[0]
        connid = buf[1:5]
        buf = buf[5:]

        if not self._initialized:
            if flag == self.NEW:
                self._initialized = True
                self._connid = connid
            else:
                if flag == self.DAT:
                    self._send_packet(self.END)

                raise EOFError('Unexpected flag')
        elif flag == self.END:
            raise EOFError('EOF Flag received')

        elif connid != self._connid:
            raise EOFError('Unexpected connection id')

        return buf

    def _write_impl(self, data, flush=True):       
        self._send_packet(self.DAT, data, flush)        
        return len(data)

    def _read_impl(self, timeout):
        if self._write_only:
            raise ValueError('Write-Only KCP Instance')

        buf = self._handle.recv()
        if buf is None:
            if timeout is not None:
                timeout = int(timeout * 1000)

            try:
                buf = self._handle.pollread(timeout)
            except OSError as e:
                raise EOFError(str(e))
        
        return self._parse_packet(buf)

    def _close_impl(self):
        self._sock.close()
        self._sock = None

    def __repr__(self):
        return 'KCPEndpoint(fd={}{})'.format(
            self._fileno, '' if self._sock else ' (closed)')


def from_uri_kcp(uri, *args, **kwargs):
    udp_uri = uri.__class__('udp', uri[1:])
    endpoint = from_uri(udp_uri, *args, **kwargs)
    return KCPEndpoint(
        endpoint, interval=kwargs.get('interval', 64)
    )


# def register(schemas):
#     schemas['kcp'] = from_uri_kcp
