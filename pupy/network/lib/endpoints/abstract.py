# -*- coding: utf-8 -*-

__all__ = (
    'AbstractNonThreadSafeEndpoint', 'AbstractEndpoint',
    'EndpointCapabilities', 'AbstractServer'
)

from shlex import split
from urlparse import urlparse, ParseResult
from threading import Thread, Lock
from network.lib import getLogger
from network.lib.streams.PupyGenericStream import PupyGenericStream


logger = getLogger('abstract')


class EndpointCapabilities(object):
    __slots__ = (
        '_max_io_chunk',
        '_native_proxies', '_supported_proxies',
        '_default_stream'
    )

    def __init__(self,
        max_io_chunk=None, native_proxies=(), supported_proxies=(),
            default_stream=PupyGenericStream):

        self._max_io_chunk = max_io_chunk
        self._supported_proxies = supported_proxies
        self._native_proxies = native_proxies
        self._default_stream = default_stream

    @property
    def max_io_chunk(self):
        return self._max_io_chunk

    @property
    def native_proxies(self):
        return self._native_proxies

    @property
    def supported_proxies(self):
        return self._supported_proxies

    @property
    def default_stream(self):
        return self._default_stream

    def __repr__(self):
        return '{}({})'.format(
            self.__class__.__name__,
            ', '.join(
                '{}={}'.format(
                    key[1:],
                    getattr(self, key)
                ) for key in self.__slots__
            )
        )


class AbstractFabric(object):
    __slots__ = (
        'transport', 'stream', 'kwargs', 'capabilities'
    )

    def __init__(self, kwargs={},
            capabilities=EndpointCapabilities()):
        self.transport = None
        self.kwargs = kwargs
        self.capabilities = capabilities
        self.stream = capabilities.default_stream if capabilities else None

    def set_transport(self, transport):
        self.transport = transport

    def set_stream(self, stream):
        self.stream = stream

    def prepare(self):
        pass

    def __call__(self, kwargs):
        raise NotImplementedError('{}.__call__ is not implemented')


class AbstractEndpoint(AbstractFabric):

    __slots__ = ('_handle', '_name')

    def __init__(self, handle, name, capabilities, **kwargs):
        self._handle = handle
        self._name = name

        super(AbstractEndpoint, self).__init__(capabilities)

    @property
    def handle(self):
        return self._handle

    @property
    def name(self):
        return self._name

    def __call__(self):
        if self.stream is None:
            raise ValueError('{}.set_stream(stream) should be called first')

        return self.stream(
            self, self.transport, self.kwargs,
            is_client=True
        )

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


class AbstractClientException(Exception):
    __slots__ = ('clients', )


class AbstractServer(AbstractFabric):
    __slots__ = (
        'uris',
        'pupy_srv',

        'active',

        'ping', 'ping_interval', 'ping_timeout',

        '_handlers_lock',
        '_initialized',
        '_clients'
    )

    def __init__(self, uris,
            pupy_srv=None, capabilities=EndpointCapabilities()):

        if isinstance(uris, str):
            uris = tuple(urlparse(uri) for uri in split(uris))
        elif isinstance(uris, ParseResult):
            uris = (uris,)
        elif hasattr(uris, '__next__'):
            uris = tuple(uris)
        else:
            raise ValueError(
                'Invalid argument "uris" - must be uri or tuple'
            )

        self.uris = uris
        self.pupy_srv = pupy_srv

        self.active = False

        self._initialized = False
        self._handlers_lock = Lock()
        self._clients = set()

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

        super(AbstractServer, self).__init__(capabilities)

    def set_transport(self, transport, kwargs={}):
        self.transport = transport
        self.kwargs = kwargs

    def set_stream(self, stream):
        raise NotImplementedError(
            '{}.set_stream(stream) is not implemented'.format(
                self.__class__.__name__
            )
        )

    def prepare(self):
        if self._initialized:
            return

        try:
            resolved = tuple(
                self._impl_resolve(uri) for uri in self.uris
            )
        except Exception as e:
            logger.exception(
                '%s.listen():_impl_resolve: %s', self.__class__.__name__, e)
            raise

        try:
            self._impl_bind(resolved)
        except Exception as e:
            logger.exception(
                '%s.listen():_impl_bind: %s', self.__class__.__name__, e)
            raise

        try:
            self._impl_listen()
            self._initialized = True
        except Exception as e:
            logger.exception(
                '%s.listen():_impl_listen: %s', self.__class__.__name__, e)
            raise

    def __call__(self):
        if not self.stream:
            raise ValueError('{}.stream must be initialized'.format(
                self.__class__.__name__))

        if not self._initialized:
            raise ValueError('{}.listen() must be called first'.format(
                self.__class__.__name__))

        thread = Thread(
            target=self._loop, name='<Listener: uri={}>'.format(self.uris))
        thread.daemon = True
        thread.start()

    def _loop(self):
        self.active = True

        try:
            while self.active:
                endpoints = self._impl_accept()
                
                for endpoint in endpoints:
                    stream = self.stream(
                        endpoint, self.transport,
                        self.kwargs,
                        is_client=False,
                        close_cb=self._impl_on_close_locked
                    )

                    if endpoint:
                        detached_rpc_handler = RPCLoop(
                            stream,
                            pupy_srv=self.pupy_srv,
                            on_verified=self._impl_on_verified_locked,
                            on_exit=self._impl_on_exit_locked
                        )

                        detached_rpc_handler.start()

        except Exception as e:
            logger.exception('%s._impl_accept: error: %s', self, e)
            raise

        finally:
            try:
                self._impl_close()
            except Exception as e:
                logger.exception('%s._impl_close(): %s',
                    self.__class__.__name__, e)
                raise

    def _impl_resolve(self, uri):
        return uri

    def _impl_listen(self):
        pass

    def _impl_bind(self, uris):
        raise NotImplementedError(
            '{}._impl_bind(uris) must be implemented'
        )

    def _impl_accept(self):
        raise NotImplementedError(
            '{}._impl_access() -> (endpoint, kwargs) must be implemented'
        )

    def _impl_on_verified_locked(self, connection):
        with self._handlers_lock:
            self._impl_on_verified(connection)
            self._clients.add(connection)

    def _impl_on_close_locked(self, connection):
        with self._handlers_lock:
            self._impl_on_close(connection)

    def _impl_on_exit_locked(self, connection):
        with self._handlers_lock:
            try:
                self._clients.remove(connection)
            finally:
                self._impl_on_exit(connection)

    def _impl_on_verified(self, connection):
        pass

    def _impl_on_close(self, connection):
        pass

    def _impl_on_exit(self, connection):
        pass

    def _impl_close(self):
        pass

    def close(self):
        if not self.active:
            return
