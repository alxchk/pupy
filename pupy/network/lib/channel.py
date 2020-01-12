# -*- coding: utf-8 -*-

__all__ = (
    'PupyChannel',
)

from threading import Lock
from zlib import (
    compress, compressobj, decompressobj
)

from network.lib import getLogger
from network.lib.buffer import Buffer
from network.lib.rpc.lib.compat import Struct

logger = getLogger('channel')


class PupyChannel(object):
    FLUSHER = b'\n'
    FRAME_HEADER = Struct('!LB')

    __slots__ = (
        'stream',
        'compress', 'compression_level', 'compression_threshold',

        '_send_channel_lock', '_recv_channel_lock'
    )

    def __init__(self, stream):
        self.stream = stream
        self.compress = True
        self.compression_level = 5
        self.compression_threshold = self.stream.MAX_IO_CHUNK
        self._send_channel_lock = Lock()
        self._recv_channel_lock = Lock()

    def close(self):
        self.stream.close()

    def poll(self, timeout):
        ready = self.stream.poll(timeout)

        if __debug__:
            logger.debug(
                '%s - %s', self, 'READY' if ready else 'NOT READY'
            )

        return ready

    def consume(self):
        if hasattr(self.stream, 'consume'):
            return self.stream.consume()

    def wake(self):
        if hasattr(self.stream, 'wake'):
            return self.stream.wake()

    def recv(self):
        if __debug__:
            logger.debug('%s: recv message - start', self)

        with self._recv_channel_lock:
            data = self._recv()

        if __debug__:
            logger.debug(
                '%s: recv message - complete (%s)', self,
                len(data) if data else 'None'
            )

        return data

    def send(self, data):
        with self._send_channel_lock:
            if __debug__:
                logger.debug('send=%s', len(data))

            self._send(data)

    def _recv(self):
        """ Recv logic with interruptions """

        # print "RECV! WAIT FOR LENGTH!"

        if __debug__:
            logger.debug('%s: Read header size - start', self)

        packet = self.stream.read(self.FRAME_HEADER.size)
        # If no packet - then just return
        if not packet:

            if __debug__:
                logger.debug('%s: Read header size - giveup - not ready', self)

            return None

        header = packet

        if __debug__:
            logger.debug('%s: Read header - start', self)

        while len(header) != self.FRAME_HEADER.size:
            packet = self.stream.read(self.FRAME_HEADER.size - len(header))
            if packet:
                header += packet
                del packet

        if __debug__:
            logger.debug('%s: Read header - done', self)

        length, compressed = self.FRAME_HEADER.unpack(header)
        # print "RECV! WAIT FOR LENGTH COMPLETE!"

        required_length = length + len(self.FLUSHER)
        # print "WAIT FOR", required_length

        decompressor = None

        if compressed:
            decompressor = decompressobj()

        buf = Buffer()

        if __debug__:
            logger.debug('%s: Read body - start - %d', self, required_length)

        while required_length:
            packet = self.stream.read(min(required_length, self.compression_threshold))
            if packet:
                required_length -= len(packet)
                # print "GET", len(packet)
                if not required_length:
                    packet = packet[:-len(self.FLUSHER)]

                if compressed:
                    packet = decompressor.decompress(packet)
                    if not packet:
                        continue

                if packet:
                    buf.write(packet)

        if __debug__:
            logger.debug('%s: Read body - done', self)

        if compressed:
            packet = decompressor.flush()
            if packet:
                buf.write(packet)

        return buf

    def _send(self, data):
        """ Smarter compression support """
        compressed = 0

        ldata = len(data)
        portion = None
        lportion = 0

        if self.compress and ldata > self.compression_threshold:
            portion = data.peek(self.compression_threshold)
            portion = compress(portion)
            lportion = len(portion)
            if lportion < self.compression_threshold:
                compressed = 1

        if not compressed:
            del portion
            self.stream.write(
                self.FRAME_HEADER.pack(ldata, compressed), notify=False
            )
            self.stream.write(data, notify=False)
            self.stream.write(self.FLUSHER)

            return

        del portion

        compressor = compressobj(self.compression_level)

        total_length = 0
        rest = ldata
        i = 0

        while rest > 0:
            cdata = data.read(self.compression_threshold)

            lcdata = len(cdata)
            rest -= lcdata
            i += lcdata

            portion = compressor.compress(cdata)
            lportion = len(portion)

            if lportion > 0:
                total_length += lportion
                self.stream.write(portion, notify=False)

        portion = compressor.flush()
        lportion = len(portion)
        if lportion:
            total_length += lportion
            self.stream.write(portion, notify=False)

        del portion, data, cdata

        self.stream.insert(self.FRAME_HEADER.pack(total_length, compressed))
        self.stream.write(self.FLUSHER)

    def __repr__(self):
        return 'PupyChannel({})'.format(self.stream)
