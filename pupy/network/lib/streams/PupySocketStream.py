# -*- coding: utf-8 -*-
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms
""" abstraction layer over rpyc streams to handle different transports and integrate obfsproxy pluggable transports """

from network.lib import getLogger
logger = getLogger('pss')

__all__ = [
    'PupySocketStream',
]

try:
    import kcp
    assert kcp

    __all__.append(
        'PupyUDPSocketStream'
    )

except ImportError:
    logger.warning('Datagram based stream is not available: KCP missing')

import os
import time
import traceback

from network.lib.buffer import Buffer
from network.lib.endpoints.abstract_socket import AbstractSocket
from network.lib.streams.PupyGenericStream import PupyGenericStream

import threading


class PupySocketStream(PupyGenericStream):
    MAX_IO_CHUNK = 32000
    KEEP_ALIVE_REQUIRED = False

    __slots__ = ()

    def __init__(self, socket, transport_args=[], transport_kwargs={}):
        super(PupySocketStream, self).__init__(
            socket if isinstance(socket, AbstractSocket) else
            AbstractSocket(socket), transport_args, transport_kwargs
        )


class PupyUDPSocketStream(object):
    NEW = '\x00'
    DAT = '\x01'
    END = '\x02'

    def __init__(self, sock, transport_class, transport_kwargs={}, client_side=True, close_cb=None, lsi=5):

        if not (type(sock) is tuple and len(sock) in (2,3)):
            raise Exception(
                'dst_addr is not supplied for UDP stream, '
                'PupyUDPSocketStream needs a reply address/port')

        self.client_side = client_side
        self.closed = False

        self.local_connid = os.urandom(4)
        self.remote_connid = None

        self.LONG_SLEEP_INTERRUPT_TIMEOUT = lsi
        self.KEEP_ALIVE_REQUIRED = lsi * 3
        self.INITIALIZED = False
        self.NEW_SENT = False

        self.sock, self.dst_addr = sock[0], sock[1]
        if len(sock) == 3:
            self.kcp = sock[2]
        else:
            if client_side:
                dst = self.sock.fileno()
            else:
                # dst = lambda data: self.sock.sendto(data, self.dst_addr)
                dst = (
                    self.sock.fileno(), self.sock.family, self.dst_addr[0], self.dst_addr[1]
                )

            self.kcp = kcp.KCP(dst, 0, interval=64)

        self.kcp.window = 32768

        self.buf_in = Buffer(shared=True)
        self.buf_out = Buffer()

        #buffers for transport
        self.upstream = Buffer(
            shared=True
        )

        self.downstream = Buffer(
            on_write=self._send,
            shared=True
        )

        self.upstream_lock = threading.Lock()
        self.downstream_lock = threading.Lock()

        self.transport = transport_class(self, **transport_kwargs)

        self.MAX_IO_CHUNK = self.kcp.mtu - (24 + 5)
        self.compress = True
        self.close_callback = close_cb

        self._wake_after = None

        self.failed = False
        try:
            self.on_connect()

        except Exception:
            self.failed = True
            raise

    def on_connect(self):
        self.transport.on_connect()

    def _send_packet(self, flag, data=''):
        need_flush = False
        if flag in (self.NEW, self.END):
            need_flush = True

        if flag == self.DAT and not self.NEW_SENT:
            flag = self.NEW
            self.NEW_SENT = True

        self.kcp.send(flag + self.local_connid + data)
        if need_flush:
            self.kcp.flush()

    def poll(self, timeout):
        if self.closed:
            return None

        return len(self.upstream)>0 or self._poll_read(timeout)

    def close(self):
        self._send_packet(self.END)

        if self.close_callback:
            self.close_callback('{}:{}'.format(
                self.dst_addr[0], self.dst_addr[1]))

        self.closed = True
        self.kcp = None

        if self.client_side:
            self.sock.close()

    def _send(self):
        """ called as a callback on the downstream.write """
        if self.closed or not self.kcp:
            raise EOFError('Connection is not established yet')

        if len(self.downstream)>0:
            while len(self.downstream) > 0:
                data = self.downstream.read(self.MAX_IO_CHUNK)
                self._send_packet(self.DAT, data)

            if self.kcp:
                self.kcp.flush()

    def _process_buf(self, buf):
        flag = buf[0]
        connid = buf[1:5]
        buf = buf[5:]

        if not self.INITIALIZED:
            if flag == self.NEW:
                self.INITIALIZED = True
                self.remote_connid = connid
            else:
                if flag == self.DAT:
                    self._send_packet(self.END)

                raise EOFError('Unexpected flag')
        elif flag == self.END:
            raise EOFError('EOF Flag received')

        elif connid != self.remote_connid:
            raise EOFError('Unexpected connection id')

        return buf

    def _poll_read(self, timeout=None):
        if not self.client_side:
            # In case of strage hangups change None to timeout
            self._wake_after = time.time() + timeout
            return self.buf_in.wait(None)

        buf = self.kcp.recv()
        if buf is None:
            if timeout is not None:
                timeout = int(timeout * 1000)

            try:
                buf = self.kcp.pollread(timeout)
            except OSError, e:
                raise EOFError(str(e))

        have_data = False
        while buf:
            buf = self._process_buf(buf)
            if buf:
                with self.buf_in:
                    self.buf_in.write(buf, notify=False)
                have_data = True

            buf = self.kcp.recv()

        if have_data:
            self.buf_in.flush()
            return True

        return False

    def read(self, count):
        if self.closed:
            return self.upstream.read(count)

        try:
            while len(self.upstream) < count:
                if self.buf_in or self._poll_read(10):
                    with self.buf_in:
                        self.transport.downstream_recv(self.buf_in)
                else:
                    break

            return self.upstream.read(count)

        except:
            logger.debug(traceback.format_exc())

    def insert(self, data):
        with self.upstream_lock:
            self.buf_out.insert(data)

    def flush(self):
        self.buf_out.flush()

    def write(self, data, notify=True):
        # The write will be done by the _upstream_recv
        # callback on the downstream buffer

        try:
            with self.upstream_lock:
                written = self.buf_out.write(data, notify)

                del data
                if notify:
                    self.transport.upstream_recv(self.buf_out)

        except:
            logger.debug(traceback.format_exc())
            raise

        return written

    def consume(self):
        data = False
        with self.downstream_lock:
            while True:
                kcpdata = self.kcp.recv()
                if kcpdata:
                    kcpdata = self._process_buf(kcpdata)
                else:
                    break

                if kcpdata:
                    with self.buf_in:
                        self.buf_in.write(kcpdata, notify=False)
                    data = True

            if not data:
                return True

        if data:
            self.buf_in.flush()

        return True

    def wake(self):
        now = time.time()
        if not self._wake_after or (now >= self._wake_after):
            with self.downstream_lock:
                self.buf_in.wake()
            self._wake_after = now + self.LONG_SLEEP_INTERRUPT_TIMEOUT
