# -*- coding: utf-8 -*-

__all__ = ('AbstractNonThreadSafeEndpoint', 'AbstractEndpoint')


class AbstractEndpoint(object):
    MAX_IO_CHUNK = 32768

    __slots__ = ('_handle', '_name')

    def __init__(self, handle, name):
        self._handle = handle
        self._name = name

    def _write_impl(self, data):
        raise NotImplementedError('{}._write_impl not implemented'.format(
            self.__class__.__name__))

    def _read_impl(self, timeout):
        raise NotImplementedError('{}._read_impl not implemented'.format(
            self.__class__.__name__))

    def _close_impl(self):
        raise NotImplementedError('{}._close_impl not implemented'.format(
            self.__class__.__name__))

    def write(self, data):
        if self._handle is None:
            raise EOFError('{} already closed'.format(self))

        return self._write_impl(data)

    def read(self, timeout):
        if self._handle is None:
            raise EOFError('{} already closed'.format(self))

        return self._read_impl(timeout)

    def close(self):
        if self._handle is not None:
            try:
                return self._close_impl()
            finally:
                self._handle = None

    def __repr__(self):
        return 'AbstractEndpoint({}, {}, klass={})'.format(
            self._handle, self._name, self.__class__.__name__)


class AbstractNonThreadSafeEndpoint(AbstractEndpoint):
    __slots__ = ('_r_lock', '_w_lock')

    def write(self, data):
        with self._w_lock:
            return self._write_impl(data)

    def read(self, timeout):
        with self._w_lock:
            return self._read_impl(timeout)

    def close(self):
        return self._close_impl()

    def __repr__(self):
        return 'AbstractNonThreadSafeEndpoint({}, {}, klass={})'.format(
            self._handle, self._name, self.__class__.__name__)
