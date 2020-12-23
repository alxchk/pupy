# -*- coding: utf-8 -*-

#                  WARNING !!!!

# __future__ will influence compiled files
# This must not be used, due to errors in standard libraries

# from __future__ import absolute_import
# from __future__ import division
# from __future__ import print_function
# from __future__ import unicode_literals

import sys
import ast
import marshal
import logging

try:
    from .PupyLogger import getLogger
    logger = getLogger('compiler')
except (ValueError, ImportError):
    # If PupyCompile imported directly (build_library_zip.py)
    logger = logging

if sys.version_info.major > 2:
    try:
        import py2c
    except ImportError:
        py2c = None

    from _frozen_importlib_external import MAGIC_NUMBER
    DEFAULT_MAGIC = MAGIC_NUMBER + (b'\x00' * 4 * 3)

    xrange = range
    unicode = str
else:
    py2c = None
    DEFAULT_MAGIC = b'\x00' * 8


class Compiler(ast.NodeTransformer):
    def __init__(self, data, path=False, main=False, docstrings=False):
        source = data
        if path:
            with open(data, 'rb') as src:
                source = src.read()

        self._main = main
        self._docstrings = docstrings

        ast.NodeTransformer.__init__(self)

        self._source_ast = None

        try:
            self._source_ast = ast.parse(source)

        except TypeError as e:
            logger.error('Invalid input: %s (%s)', data, e)
            raise

        except SyntaxError as e:
            if path:
                logger.error(
                    'Compilation error: %s %s:%s', e.msg, data, e.lineno
                )
            else:
                logger.error(
                    'Compilation error: %s line: %s',
                    e.msg, source.split('\n')[e.lineno]
                )

    def compile(self, filename, obfuscate=False, raw=False, magic=DEFAULT_MAGIC):
        if self._source_ast is None:
            return None

        try:
            body = marshal.dumps(
                compile(self.visit(self._source_ast), filename, 'exec')
            )
        except Exception as e:
            raise ValueError('Compilation failed: {}: {}'.format(filename, e))

        if obfuscate:
            body_len = len(body)
            offset = 0 if raw else 8

            output = bytearray(body_len + 8)
            for i, x in enumerate(body):
                output[i+offset] = (
                    ord(x) ^ ((2 ** ((65535 - i) % 65535)) % 251)
                )

            if raw:
                for i in xrange(8):
                    output[i] = 0

            return output

        elif raw:
            return body

        else:
            return magic + body

    def visit_If(self, node):
        if hasattr(node.test, 'id') and node.test.id == '__debug__':
            if node.orelse:
                return node.orelse
            else:
                return [
                    ast.Pass(
                        lineno=node.lineno,
                        col_offset=node.col_offset
                    )
                ]
        if not self._main and type(node.test) == ast.Compare \
            and type(node.test.left) == ast.Name \
                and node.test.left.id == '__name__':
            for comparator in node.test.comparators:
                if type(comparator) == ast.Str and comparator.s == '__main__':
                    return node.orelse
        elif hasattr(node.test, 'operand') and type(node.test.op) == ast.Not \
            and type(node.test.operand) == ast.Name and \
                node.test.operand.id == '__debug__':
            return node.body

        return node

    def visit_Expr(self, node):
        if type(node.value) == ast.Call and type(
            node.value.func) == ast.Attribute and type(
                node.value.func.value) == ast.Name and \
                    node.value.func.value.id == 'logging' and \
                        node.value.func.attr == 'debug':
            return None
        elif (type(node.value) == ast.Str):
            if not self._docstrings:
                node.value.s = ""

        return node

    def visit_Assign(self, node):
        if self._docstrings:
            return node

        if (type(node.value) == ast.Str) and all(
                type(target) == ast.Name and target.id in (
                    '__copyright__', '__doc__')
                for target in node.targets):
            node.value.s = ''

        return node


def py2compile(data, filename, obfuscate=False, raw=False, debug=False):
    body = py2c.compile(data, filename, 0 if debug else 2)

    if obfuscate:
        body_len = len(body)
        offset = 0 if raw else 8

        output = bytearray(body_len + 8)
        for i, x in enumerate(body):
            output[i+offset] = (x ^ ((2 ** ((65535-i) % 65535)) % 251))

        if raw:
            for i in xrange(8):
                output[i] = 0

        return output

    elif raw:
        return body

    else:
        magic = b'\x00'*8
        return magic + body


def pupycompile(
    data, filename='', path=False, obfuscate=False,
        raw=False, debug=False, main=False, target=None):

    if target is not None:
        major, minor = target

        if sys.version_info.major != major or sys.version_info.minor != minor:
            if major == 2:
                if py2c is None:
                    raise NotImplementedError(
                        'Support for bytecode cross-compilation is not '
                        'supported without py2c'
                    )

                if path is True:
                    data = open(data, 'rb').read()

                return py2compile(data, filename, obfuscate, raw, debug)

            elif major == 3 and minor < 6:
                raise NotImplementedError(
                    'Support for this target is not implemented (yet?)'
                )

    if not debug:
        logger.info(data if path else filename)
        data = Compiler(data, path, main).compile(filename, obfuscate, raw)
    else:
        source = data
        if path:
            with open(data, 'rb') as sfile:
                source = sfile.read()

        logger.info('debug: %s', data if path else filename)
        data = marshal.dumps(compile(source, filename, 'exec'))

    if data is None:
        raise ValueError('Compilation failed (debug={})'.format(debug))

    return data


if __name__ == '__main__':
    import argparse
    import os
    import stat
    import sys
    import imp
    import struct

    WHITELIST = (
        'c_parser'
    )

    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--fake-file-path', default=False, action='store_true', help='Fake file path (number)')
    parser.add_argument('-M', '--delete-main', default=False, action='store_true', help='Remove __main__')
    parser.add_argument('-D', '--delete-docstrings', default=False, action='store_true', help='Detele __doc__')
    parser.add_argument('files', metavar='<file.py>', nargs='+', help='File(s) to compile')
    args = parser.parse_args(sys.argv[1:])

    def pcompile(fake_filepath, filepath, main=False, docstrings=False):
        logger.info(filepath)
        filepath_noext, ext = os.path.splitext(filepath)
        filepath_basename = os.path.basename(filepath_noext)

        if filepath_basename in WHITELIST:
            main = True
            docstrings = True

        try:
            with open(filepath_noext + '.pyo', 'wb') as out:
                mtime = int(os.stat(filepath).st_mtime)
                out.write(Compiler(filepath, True, main, docstrings).compile(
                    fake_filepath or filepath, False, False,
                    struct.pack('<4sl', imp.get_magic(), mtime)))

        except (OSError, IOError, SyntaxError) as e:
            logger.error('%s: %s', filepath, e)

    fid = 0

    for f in args.files:
        if stat.S_ISDIR(os.stat(f).st_mode):
            for root, _, files in os.walk(f):
                for ff in files:
                    if not ff.endswith('.py'):
                        continue

                    ff = os.path.join(root, ff)

                    if args.fake_file_path:
                        fname = 'f:{}'.format(fid)
                        fid += 1
                    else:
                        fname = ff

                    pcompile(
                        fname, ff,
                        not args.delete_main,
                        not args.delete_docstrings
                    )

        else:
            if args.fake_file_path:
                fname = 'f:{}'.format(fid)
            else:
                fname = f
                fid += 1

            pcompile(
                fname, f,
                not args.delete_main,
                not args.delete_docstrings
            )
