# -*- coding: utf-8 -*-

__all__ = (
    'from_uri',
)

from urlparse import urlparse, ParseResult
from pkgutil import iter_modules
from importlib import import_module

SCHEMAS = None


def _registered_schemas():
    global SCHEMAS

    if SCHEMAS is not None:
        return SCHEMAS

    SCHEMAS = {}

    for info in iter_modules(__path__):
        _, module_name, _ = info
        try:
            module = import_module(__name__ + '.' + module_name)
        except ImportError:
            continue

        if hasattr(module, 'register'):
            module.register(SCHEMAS)

    return SCHEMAS


def from_uri(uri, *args, **kwargs):
    if not isinstance(uri, ParseResult):
        uri = urlparse()

    handler = _registered_schemas().get(uri.schema.lower())

    if not handler:
        raise ValueError('Unregistered schema {}'.format(
            repr(uri.schema.lower())))

    return handler(uri, *args, **kwargs)
