# -*- coding: utf-8 -*-

__all__ = (
    'AbstractNonThreadSafeEndpoint', 'AbstractEndpoint',
    'EndpointCapabilities', 'AbstractServer'
)

from threading import Thread, Lock

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


class AbstractServerInitWatchdog(Thread):
    def __init__(self):
        pass


class RPCLoop(Thread):
    __slots__ = (
        'connection', 'on_verified', 'on_exit', 'pupy_srv'
    )

    def __init__(self, connection, pupy_srv=None, on_verified=None, on_exit=None):
        self.connection = connection

        self.pupy_srv = pupy_srv
        self.on_verified = on_verified
        self.on_exit = on_exit

        super(RPCLoop, self).__init__()

        self.daemon = True
        self.name = 'RPCLoop({})'.format(self.connection)

    def run(self):
        try:
            self.connection.init()
            self.connection.loop()
        finally:
            try:
                if self.on_exit:
                    self.on_exit(self)
            except Exception:
                pass


class AbstractConnectionMaker(object):
    __slots__ = (
        'transport', 'stream'
    )

    def __init__(self, transport, stream):
        self.transport = transport
        self.stream = stream

    def __call__(self, endpoint, kwargs):
        # Connection = Endpoint + transports + stream

        return self.stream(
            endpoint, transport, kwargs
        )


class AbstractServer(Thread):
    __slots__ = (
        'pupy_srv',
        'transport_class', 'transport_kwargs',
        'active', '_handlers_lock'
    )

    def __init__(self, pupy_srv, transport_class, transport_kwargs):
        self.pupy_srv = pupy_srv
        self.transport_class = transport_class
        self.transport_kwargs = transport_kwargs
        self.active = False

        self._handlers_lock = Lock()

        super(AbstractServer, self).__init__()
        self.daemon = True

    def listen(self):
        pass

    def run(self):
        self.active = True

        try:
            while self.active:
                endpoint = self._imp_accept()
                if endpoint:
                    RPCLoop(
                        endpoint,
                        pupy_srv=self.pupy_srv,
                        on_verified=self._impl_on_verified_locked,
                        on_exit=self._impl_on_exit_locked
                    ).start()
        finally:
            self._impl_on_exit()

    def _imp_accept(self):
        raise NotImplementedError('{}._imp_access() not implemented')

    def _impl_on_verified_locked(self, connection):
        with self._handlers_lock:
            self._impl_on_verified(connection)

    def _impl_on_exit_locked(self, connection):
        with self._handlers_lock:
            self._impl_on_exitconnection)

    def _impl_on_verified(self, connection):
        pass

    def _impl_on_exit(self, connection):
        pass

    def close(self):
        self.active = False
