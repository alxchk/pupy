# -*- coding: utf-8 -*-

from struct import Struct
from threading import Lock

from ctypes import (
    CDLL, POINTER, byref, create_string_buffer,
    get_last_error
)

from ctypes.windll import (
    HANDLE, BOOL, DWORD, ULONG, LPSTR
)

from .abstract import AbstractNonThreadSafeEndpoint


wtsapi32 = CDLL('Wtsapi32.dll', use_last_error=True)

WTS_CURRENT_SESSION = -1
WTS_CHANNEL_OPTION_DYNAMIC = 1
WTS_CHANNEL_OPTION_DYNAMIC_PRI_MED = 0x00000002
WTS_CHANNEL_OPTION_DYNAMIC_NO_COMPRESS = 0x00000008

WAIT_TIMEOUT = 258

WTSVirtualChannelOpenEx = wtsapi32.WTSVirtualChannelOpenEx
WTSVirtualChannelOpenEx.restype = HANDLE
WTSVirtualChannelOpenEx.argtypes = (
    DWORD, LPSTR, DWORD
)

WTSVirtualChannelClose = wtsapi32.WTSVirtualChannelClose
WTSVirtualChannelClose.restype = BOOL
WTSVirtualChannelClose.argtypes = (
    HANDLE,
)

WTSVirtualChannelRead = wtsapi32.WTSVirtualChannelRead
WTSVirtualChannelRead.restype = BOOL
WTSVirtualChannelRead.argtypes = (
    HANDLE, ULONG, LPSTR, ULONG, POINTER(ULONG)
)

WTSVirtualChannelWrite = wtsapi32.WTSVirtualChannelRead
WTSVirtualChannelWrite.restype = BOOL
WTSVirtualChannelWrite.argtypes = (
    HANDLE, LPSTR, ULONG, POINTER(ULONG)
)


MarkerHeader = Struct('>II')
WTS_C_OK = 1
WTS_C_EOF = 1


class WTSException(EOFError):
    pass


class WTSDVC(AbstractNonThreadSafeEndpoint):
    __slots__ = ('_session',)

    def __init__(self, wtsname='WTS2SOCK', session=WTS_CURRENT_SESSION, timeout=5):

        handle = WTSVirtualChannelOpenEx(
            session, wtsname,
            WTS_CHANNEL_OPTION_DYNAMIC | \
                WTS_CHANNEL_OPTION_DYNAMIC_PRI_MED | \
                WTS_CHANNEL_OPTION_DYNAMIC_NO_COMPRESS
        )

        if not handle:
            raise WTSException('DVC {} can not be open'.format(wtsname))

        self._session = session
        super(WTSDVC, self).__init__(handle, wtsname)

        # Read header to enusre channel was connected
        self.read(timeout, 0)

    def __repr__(self):
        return 'WTSDVC({}, {})'.format(self._name, self._session)

    def _write_impl(self, data):
        dwWritten = DWORD(0)

        header = MarkerHeader.pack(WTS_C_OK, len(data))
        result = WTSVirtualChannelWrite(
            self._handle, header, len(header), byref(dwWritten)
        )

        if result:
            result = WTSVirtualChannelWrite(
                self._handle, data, len(data), byref(dwWritten)
                )

        return dwWritten.value

    def _read_impl(self, timeout):
        dwBytesRead = DWORD()
        cMarker = create_string_buffer(MarkerHeader.size)

        result = WTSVirtualChannelRead(
            self._handle, timeout, cMarker,
            len(cMarker), byref(dwBytesRead)
        )

        if not result:
            error = get_last_error()
            if error == WAIT_TIMEOUT:
                return

            raise WTSException('Read error: {}'.format(error))


        if dwBytesRead.value != MarkerHeader.size:
            raise WTSException('Incomplete marker read ({})'.format(
                dwBytesRead.value))

        state, dwPayloadSize = MarkerHeader.unpack(cMarker.raw)
        if state != WTS_C_OK:
            raise WTSException('Invalid channel state ({})'.format(state))

        if not dwPayloadSize:
            return

        cBuffer = create_string_buffer(dwPayloadSize)
        dwBytesRead = DWORD(dwPayloadSize)

        result = WTSVirtualChannelRead(
            self._handle, timeout, cBuffer,
            dwPayloadSize, byref(dwBytesRead)
        )

        if not result:
            raise WTSException('Read error: {}', get_last_error())

        if dwBytesRead.value != dwPayloadSize:
            raise WTSException('Incomplete read: {}/{}'.format(
                dwBytesRead, dwPayloadSize))

        return cMarker

    def close(self):
        if self._handle is not None:
            WTSVirtualChannelClose(self._handle)

        self._handle = None

    def __del__(self):
        self.close()
