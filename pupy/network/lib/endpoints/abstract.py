# -*- coding: utf-8 -*-

__all__ = (
    'AbstractNonThreadSafeEndpoint', 'AbstractEndpoint',
    'EndpointCapabilities'
)

from threading import Lock
from network.lib.streams.PupyGenericStream import PupyGenericStream


class EndpointCapabilities(object):
    __slots__ = (
        'max_io_chunk',
        'native_proxies', 'supported_proxies',
        'default_stream'
    )

    def __init__(self,
        max_io_chunk=None, native_proxies=(), supported_proxies=(),
            default_stream=PupyGenericStream):
        
        self.max_io_chunk = max_io_chunk
        self.supported_proxies = supported_proxies
        self.native_proxies = native_proxies
        self.default_stream = default_stream

    def __repr__(self):
        return '{}({})'.format(
            self.__class__.__name__,
            ', '.join(
                '{}={}'.format(
                    key,
                    getattr(self, key)
                ) for key in self.__slots__
            )
        )


class AbstractEndpoint(object):

    __slots__ = ('_handle', '_name', 'capabilities')

    def __init__(self, handle, name, **kwargs):
        self.capabilities = EndpointCapabilities(kwargs)

        self._handle = handle
        self._name = name

    @property
    def handle(self):
        return self._handle

    @property
    def name(self):
        return self._name

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

    def __init__(self, *args, **kwargs):
        self._r_lock = Lock()
        self._w_lock = Lock()

        super(AbstractNonThreadSafeEndpoint, self).__init__(
            *args, **kwargs
        )

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


class AbstractServer(object):
    __slots__ = (
        'pupy_srv',
        'transport_class', 'transport_kwargs',
        'active'
    )

    def __init__(self, pupy_srv, transport_class, transport_kwargs):
        self.pupy_srv = pupy_srv
        self.transport_class = transport_class
        self.transport_kwargs = transport_kwargs
        self.active = False

    def listen(self):
        pass

    def start(self):
        self.active = True

        try:
            while self.active:
                self._impl_loop()
        finally:
            self._impl_on_exit()

    def _impl_loop(self):
        pass

    def _impl_on_exit(self):
        pass

    def close(self):
        self.active = False
