# -*- coding: utf-8 -*-

__all__ = [
    'PupyGenericStream'
]

from threading import Lock
from traceback import extract_stack

from network.lib.buffer import Buffer
from network.lib import getLogger


logger = getLogger('pgs')


class PupyGenericStream(object):
    KEEP_ALIVE_REQUIRED = False
    compress = True

    __slots__ = (
        '_ep',
        'upstream', 'downstream',
        'upstream_lock', 'downstream_lock',
        'transport', 'transport_class', 'transport_kwargs',
        'buf_in', 'buf_out',
        'closed', 'failed'
    )

    def __init__(self, endpoint, transport_class, transport_kwargs={}):
        self._ep = endpoint

        self.closed = False
        self.failed = False

        # buffers for transport
        self.upstream = Buffer(shared=True)
        self.downstream = Buffer(
            on_write=self._flush_to_ep,
            shared=True
        )

        self.upstream_lock = Lock()
        self.downstream_lock = Lock()

        self.transport_class = transport_class
        self.transport_kwargs = transport_kwargs

        # buffers for streams
        self.buf_in = Buffer(
            on_write=self._flush_to_downstream
        )
        self.buf_out = Buffer()

        self.transport = transport_class(self, **transport_kwargs)

        logger.debug('Allocated (%s)', self)

        try:
            self.on_connect()

        except Exception:
            self.failed = True
            raise

    def on_connect(self):
        self.transport.on_connect()
        self._flush_to_ep()

    def _flush_to_ep(self):
        if __debug__:
            flushed = False

        while self.downstream and not self.closed:
            if __debug__:
                flushed = True
                logger.debug(
                    '%s: Flush to endpoint - %d',
                    self, len(self.downstream))

            self.downstream.write_to(self._ep)

        self._check_eof()

        if __debug__:
            if flushed:
                logger.debug('%s: Flushed', self)

    def _flush_to_downstream(self):
        if not self.buf_in:
            return

        if __debug__:
            logger.debug('%s: Flush to downstream - %d', self, len(self.buf_in))

        self.transport.downstream_recv(self.buf_in)

    def write(self, data, notify=True):
        written = 0

        if __debug__:
            logger.debug('stream: write=%s / n=%s',
                len(data) if data else None, notify)

        try:
            with self.upstream_lock:
                written = self.buf_out.write(data, notify)

                del data

                if notify:
                    self.transport.upstream_recv(self.buf_out)

        except EOFError:
            if __debug__:
                logger.debug('%s: EOF during write', self)

            self.close()
            raise

        except Exception as e:
            logger.exception('%s: Error during write: %s', self, e)
            self.close()
            raise

        return written

    def _check_eof(self):
        if self.closed:
            logger.debug('EOF (%s)', self)
            raise EOFError('PupyWTSStream closed')

    def poll(self, timeout):
        self._check_eof()
        return len(self.upstream)>0 or self._poll_wait(timeout)

    def _poll_wait(self, timeout=60):
        logger.debug('Poll (%s) start (timeout=%s)', self, timeout)

        try:
            parcel = self._ep.read(timeout)
        except EOFError:
            logger.debug('Poll (%s) failed with EOF', self)
            self.close()
            raise

        if parcel:
            if __debug__:
                logger.debug('Poll (%s) completed: len=%d', self, len(parcel))
            self.buf_in.write(parcel)
            return True
        else:
            if __debug__:
                logger.debug('Poll (%s) completed: no data', self)

        return False

    def read(self, count):
        logger.debug('Read (%s) - %s / %s - start',
            self, count, len(self.upstream))

        self._check_eof()

        data = self.upstream.read(count)

        if not data and self._poll_wait():
            data = self.upstream.read(count)

        self._check_eof()

        logger.debug('Read (%s) - %s / %s - done - %s',
            self, count, len(self.upstream), len(data) if data else 'EMPTY')

        return data

    def insert(self, data):
        logger.debug('Insert (%s): %s', self, len(data))

        self._check_eof()

        with self.upstream_lock:
            self.buf_out.insert(data)

    def flush(self):
        logger.debug('Flush (%s)')

        self.buf_out.flush()
        self._check_eof()

    def close(self):
        if __debug__:
            stack = extract_stack()
            if len(stack) > 2:
                logger.debug('Close(%s) (at: %s:%s %s(%s))',
                    self, *stack[-2])

        self.closed = True
        self.upstream.wake()

    def __repr__(self):
        return 'PupyGenericStream({})'.format(self._ep)
