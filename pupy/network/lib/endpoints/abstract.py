# -*- coding: utf-8 -*-

__all__ = (
    'AbstractEndpoint', 'AbstractClientEndpoint',
    'EndpointCapabilities', 'AbstractServer',
    'Keywords', 'Schemes'
)

from shlex import split
from urlparse import urlparse, ParseResult
from threading import Thread, Lock
from collections import namedtuple

from network.lib import getLogger
from network.lib.streams.PupyGenericStream import PupyGenericStream


logger = getLogger('abstract')


class KeywordDescription(object):
    __slots__ = (
        'name', 'description', 'default_value', 'default_type'
    )

    def __init__(self, name, description, default_type=str, default_value=None):
        self.name = name
        self.description = description
        self.default_value = default_value
        self.default_type = default_type

    def from_string(self, value):
        if issubclass(self.default_type, str):
            return value
        elif issubclass(self.default_type, int):
            value = value.lower()
            if value.startswith('0x'):
                return int(value[2:], 16)
            elif value.startswith('0b'):
                return int(value[2:], 2)
            elif value.startswith('0o'):
                return int(value[2:], 8)
            else:
                return int(value)
        elif issubclass(self.default_type, bool):
            value = value.lower()
            if value in ('0', '-1', 'n', 'no', 'false', 'off', 'disable'):
                return False
            else:
                return True


class Keywords(object):
    __slots__ = (
        '_descriptions',
    )

    def __init__(self, *descriptions):
        self._descriptions = {}

        for description in descriptions:
            if isinstance(description, KeywordDescription):
                self._descriptions[description.name] = description
            else:
                description = KeywordDescription(*description)
                self._descriptions[description.name] = description

    def from_kwargs(self, kwargs):
        return {
            description.name:(
                description.from_string(kwargs[description.name])
                if description.name in kwargs else
                description.default_value
            ) for description in self._descriptions.values()
        }

    def descriptions(self):
        return {
            description.name: description.help
            for description in self._descriptions
        }

    def __iadd__(self, keywords):
        if not isinstance(keywords, Keywords):
            raise ValueError('Unsupported value')

        for key, value in keywords._descriptions.iteritems():
            if key not in self._descriptions:
                self._descriptions[key] = value

        return self


class Schemes(object):
    __slots__ = (
        'schemes',
    )

    def __init__(self, *schemes):
        self.schemes = {
            name.lower(): description
            for (name, description) in schemes
        }

    def from_parsed_uri(self, uri):
        if not uri.scheme:
            raise ValueError('Invalid URI')

        scheme = uri.scheme.lower()
        if '+' in scheme:
            scheme = scheme.split('+', 1)[0]

        if scheme in self.schemes:
            return scheme

        return None


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
    def max_io_size(self):
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


class AbstractEndpoint(object):
    __slots__ = (
        'uri',
        'transport', 'transport_kwargs',
        'stream', 'capabilities',

         '_name'
    )

    SCHEMES = Schemes()

    def __init__(self, uri, capabilities=None, name=None):
        self.uri = uri
        self.transport = None
        self.transport_kwargs = {}
        self.capabilities = capabilities or EndpointCapabilities()
        self.stream = capabilities.default_stream if capabilities else None

        self._name = name or str(id(self))

    @classmethod
    def create(cls, uri, kwargs, capabilities=None):
        return cls(
            uri, capabilities, **cls.keywords().from_kwargs(kwargs)
        )

    @classmethod
    def keywords(cls):
        return Keywords()

    @classmethod
    def schemes(cls):
        return cls.SCHEMES.schemes

    @classmethod
    def supports_uri(cls, uri):
        return bool(cls.SCHEMES.from_parsed_uri(uri))

    @classmethod
    def is_client(cls):
        raise NotImplementedError(
            '{}.is_client() not implemented'.format(
                cls.__name__
            )
        )

    @classmethod
    def is_server(cls):
        raise NotImplementedError(
            '{}.is_server() not implemented'.format(
                cls.__name__
            )
        )

    @property
    def name(self):
        return self._name

    def set_transport(self, transport, credentials, kwargs):
        self.transport = transport

        kwargs = dict(kwargs)
        kwargs['credentials'] = credentials
        self.transport_kwargs = kwargs

    def set_stream(self, stream):
        self.stream = stream

    def prepare(self):
        pass

    def __call__(self, kwargs):
        raise NotImplementedError('{}.__call__ is not implemented')

    def __repr__(self):
        return '<{} (name={} handle={})>'.format(
            self.__class__.__name__, self._name, self.handle)



class AbstractClientEndpoint(AbstractEndpoint):
    __slots__ = (
        '_handle', '_name', '_closed', '_once'
    )

    def __init__(self, uri, capabilities=None, handle=None, name=None):

        self._handle = handle
        self._closed = False
        self._once = Lock()

        super(AbstractClientEndpoint, self).__init__(
            uri, capabilities, name
        )

    @classmethod
    def is_client(cls):
        return True

    @classmethod
    def is_server(cls):
        return False

    @property
    def handle(self):
        return self._handle

    @property
    def closed(self):
        return self._closed

    def prepare(self):
        if self._handle:
            return

        self._closed = False

        self._handle, self._name = self._create_handle_impl()

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


class AbstractNonThreadSafeClient(AbstractClientEndpoint):
    __slots__ = ('_r_lock', '_w_lock')

    def __init__(self, *args, **kwargs):
        self._r_lock = Lock()
        self._w_lock = Lock()

        super(AbstractNonThreadSafeClient, self).__init__(
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
        return '<{}({}, {})>'.format(
            self.__class__.__name__, self._handle, self._name)


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


class AbstractServer(AbstractEndpoint):
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
            self.ping = ping and ping.lower() not in (
                '0', '-1', 'n', 'false', 'no'
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

        super(AbstractServer, self).__init__(
            self._split_uri(uris), capabilities
        )

    @classmethod
    def is_client(cls):
        return False

    @classmethod
    def is_server(cls):
        return True

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

    def prepare(self):
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

    def _impl_resolve(self):
        return self.uris

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
