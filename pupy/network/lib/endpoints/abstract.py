# -*- coding: utf-8 -*-

__all__ = (
    'AbstractNonThreadSafeEndpoint', 'AbstractEndpoint',
    'EndpointCapabilities', 'AbstractServer'
)

from threading import Thread, Lock
from network.lib import getLogger
from network.lib.streams.PupyGenericStream import PupyGenericStream


logger = getLogger('abstract')


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
        'transport', 'kwargs', 'stream'
    )

    def __init__(self, transport, stream, kwargs={}):
        self.transport = transport
        self.stream = stream
        self.kwargs = kwargs

    def __call__(self, endpoint, kwargs=None):
        # Connection = Endpoint + transports + stream

        if kwargs:
            kwargs = dict(self.kwargs).update(kwargs)
        else:
            kwargs = self.kwargs

        return self.stream(
            endpoint, self.transport, kwargs
        )


class AbstractServer(Thread):
    __slots__ = (
        'pupy_srv',
        'transport_class', 'transport_kwargs',
        'active',

        'ping', 'ping_interval', 'ping_timeout',
        
        '_handlers_lock', '_connection_maker',
        '_initialized'
    )

    connection_maker = AbstractConnectionMaker

    def __init__(self,
            pupy_srv, transport_class, transport_kwargs={}):

        self.pupy_srv = pupy_srv
        self.transport_class = transport_class
        self.transport_kwargs = transport_kwargs
        self.active = False

        self._initialized = False
        self._handlers_lock = Lock()
        self._connection_maker = self.connection_maker(
            transport_class, transport_kwargs
        )

        if self.pupy_srv and self.pupy_srv.config:
            ping = self.pupy_srv.config.get('pupyd', 'ping')
            self.ping = ping and ping not in (
                '0', '-1', 'N', 'n', 'false', 'False', 'no', 'No'
            )
        else:
            self.ping = False

        if self.ping:
            try:
                self.ping_interval = int(ping)
            except:
                self.ping_interval = 2

            if self.pupy_srv:
                self.ping_timeout = self.pupy_srv.config.get(
                    'pupyd', 'ping_interval')
            else:
                self.ping_timeout = self.ping_interval * 10
        else:
            self.ping_interval = None
            self.ping_timeout = None

        super(AbstractServer, self).__init__()
        self.daemon = True

    def listen(self):
        if self._initialized:
            return

        try:
            self._impl_listen()
            self._initialized = True
        except Exception as e:
            logger.exception(
                '%s.listen(): %s', self.__class__.__name__, e)
            raise

    def run(self):
        self.active = True

        try:
            while self.active:
                endpoint, kwargs = self._impl_accept()
                stream = self._connection_maker(endpoint, kwargs)

                if endpoint:
                    detached_rpc_handler = RPCLoop(
                        stream,
                        pupy_srv=self.pupy_srv,
                        on_verified=self._impl_on_verified_locked,
                        on_exit=self._impl_on_exit_locked
                    )

                    detached_rpc_handler.start()
        finally:
            try:
                self._impl_close()
            except Exception as e:
                logger.exception('%s._impl_close(): %s', 
                    self.__class__.__name__, e)
                raise

    def _impl_listen(self):
        raise NotImplementedError(
            '{}._impl_listen() must be implemented'
        )

    def _impl_accept(self):
        raise NotImplementedError(
            '{}._impl_access() -> (endpoint, kwargs) must be implemented'
        )

    def _impl_on_verified_locked(self, connection):
        with self._handlers_lock:
            self._impl_on_verified(connection)

    def _impl_on_exit_locked(self, connection):
        with self._handlers_lock:
            self._impl_on_exit(connection)

    def _impl_on_verified(self, connection):
        pass

    def _impl_on_exit(self, connection):
        pass

    def _impl_close(self):
        pass

    def close(self):
        if not self.active:
            return
