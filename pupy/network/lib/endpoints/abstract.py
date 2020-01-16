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
        'uri',
        'transport', 'transport_kwargs',
        'stream', 'capabilities'
    )

    def __init__(self, uri, capabilities=None, kwargs={}):
        self.uri = uri
        self.transport = None
        self.transport_kwargs = {}
        self.capabilities = capabilities or EndpointCapabilities()
        self.stream = capabilities.default_stream if capabilities else None

    def set_transport(self, transport, kwargs):
        self.transport = transport
        self.transport_kwargs = kwargs

    def set_stream(self, stream):
        self.stream = stream

    def prepare(self):
        pass

    def __call__(self, kwargs):
        raise NotImplementedError('{}.__call__ is not implemented')


class AbstractEndpoint(AbstractFabric):
    __slots__ = (
        '_handle', '_name', '_closed', '_once'
    )

    def __init__(self, uri, capabilities=None, handle=None, name=None):

        self._handle = handle
        self._name = name
        self._closed = False
        self._once = Lock()

        super(AbstractEndpoint, self).__init__(uri, capabilities)

    @property
    def handle(self):
        return self._handle

    @property
    def closed(self):
        return self._closed

    @property
    def name(self):
        return self._name

    def prepare(self, *args, **kwargs):
        if self._handle:
            return

        self._closed = False

        self._handle, self._name = self._create_handle_impl(
            *args, **kwargs
        )

    def __call__(self, is_client=True, close_cb=None):
        if self._closed:
            raise ValueError('{} already closed')
        elif self.stream is None:
            raise ValueError('{}.set_stream(stream) must be called first')
        elif self._handle is None:
            raise ValueError('{}.prepare() must be called first')

        return self.stream(
            self, self.transport, self.transport_kwargs,
            is_client=is_client,
            close_cb=close_cb
        )

    def _create_handle_impl(self, *args, **kwargs):
        raise NotImplementedError(
            '{}._create_handle_impl() -> (handle, name) not implemented'.format(
                self.__class__.__name__))

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
        if self._closed:
            raise EOFError('{} already closed'.format(self))
        elif self._handle is None:
            raise EOFError('{} is not initialized'.format(self))

        return self._write_impl(data)

    def read(self, timeout):
        if self._closed:
            raise EOFError('{} already closed'.format(self))
        elif self._handle is None:
            raise EOFError('{} is not initialized'.format(self))

        return self._read_impl(timeout)

    def close(self):
        if not self._closed:
            with self._once:
                if self._closed:
                    return

                self._closed = True

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

        if uris:
            self._set_uris(uris)

        super(AbstractServer, self).__init__(
            self._split_uri(uri), capabilities
        )

    def _split_uri(self, uri):
        if isinstance(uri, str):
            return tuple(urlparse(uri) for uri in split(uri))
        elif isinstance(uri, ParseResult):
            return (uri,)
        elif hasattr(uri, '__next__'):
            return tuple(uri)
        else:
            raise ValueError(
                'Invalid argument "uri" - must be uri or tuple'
            )

    def set_transport(self, transport, kwargs={}):
        self.transport = transport
        self.transport_kwargs = kwargs

    def set_stream(self, stream):
        raise NotImplementedError(
            '{}.set_stream(stream) is not implemented'.format(
                self.__class__.__name__
            )
        )

    def prepare(self, *args, **kwargs):
        if self._initialized:
            return

        try:
            resolved = tuple(
                self._impl_resolve(uri) for uri in self.uri
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
            target=self._loop, name='<Listener: uri={}>'.format(self.uri))
        thread.daemon = True
        thread.start()

    def _loop(self):
        self.active = True

        try:
            while self.active:
                endpoints = self._impl_accept()

                endpoints.set_stream(self.stream)
                endpoints.set_transport(
                    self.transport, self.transport_kwargs
                )

                for endpoint in endpoints:
                    stream = endpoint(
                        is_client=False,
                        close_cb=self._impl_on_close_locked
                    )

                    if stream:
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
