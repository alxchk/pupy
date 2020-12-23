#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import os
import sys
import zlib
import marshal

from zipfile import ZipFile

from elftools.elf.elffile import ELFFile
from io import BytesIO

from pupylib.PupyCompile import pupycompile
from pupylib.utils.arch import is_native
from pupylib import ROOT, getLogger

from network.lib.convcompat import reprb


if sys.version_info.major > 2:
    import pickle
    from os import getcwd

    xrange = range

else:
    import cPickle as pickle
    from os import getcwdu as getcwd


class BinaryObjectError(ValueError):
    pass


class UnsafePathError(ValueError):
    pass


class NotFoundError(NameError):
    pass


class IgnoreFileException(Exception):
    pass


class Target(object):
    __slots__ = (
        'os', 'arch', 'pymaj', 'pymin', 'debug',
        '_native', '_so', '_platform'
    )

    def __init__(self, python, platform=None, debug=False):
        self.pymaj, self.pymin = python[:2]
        self.debug = debug

        self.pymaj = int(self.pymaj)
        self.pymin = int(self.pymin)

        if platform:
            self.os, self.arch = platform[:2]

            self.os = self.os.strip().lower()
            self.arch = self.arch.strip().lower()

            self._native = is_native(
                self.os, self.arch, python
            )

            sover = '{}.{}'.format(self.pymaj, self.pymin)
            if self.pymaj > 3:
                sover += 'm'
            self._so = 'libpython{}.so.1.0'.format(sover)
        else:
            self.os = None
            self.arch = None
            self._native = False

    @property
    def native(self):
        return self._native

    @property
    def so(self):
        return self._so

    @property
    def pyver(self):
        return (self.pymaj, self.pymin)

    @property
    def platform(self):
        if self.os and self.arch:
            return (self.os, self.arch)
        else:
            return None

    @property
    def pyver_str(self):
        return '{}{}'.format(self.pymaj, self.pymin)

    def __repr__(self):
        if self.os and self.arch:
            platform = (self.os, self.arch)
        else:
            platform = None

        return 'Target(({}, {}), {}, {})'.format(
            repr(self.pymaj), repr(self.pymin),
            repr(platform), repr(self.debug)
        )


logger = getLogger('deps')

LIBS_AUTHORIZED_PATHS = [
    x for x in sys.path if x != ''
] + [
    os.path.join(ROOT, 'packages'),
    'packages'
]

# ../libs - for windows bundles, to use simple zip command
# site-packages/win32 - for pywin32
COMMON_SEARCH_PREFIXES = (
    '',
    'site-packages/win32/lib',
    'site-packages/win32',
    'site-packages/pywin32_system32',
    'site-packages',
    'lib-dynload'
)

COMMON_MODULE_ENDINGS = (
    '/', '.py', '.pyo', '.pyc'
)

IGNORED_ENDINGS = (
    'tests', 'test', 'SelfTest', 'examples', 'demos', '__pycache__'
)

# TODO: ADD PY2/PY3 deps

# dependencies to load for each modules
WELL_KNOWN_DEPS = {
    'pupyps': {
        'windows': ['pupwinutils.security']
    },
    'pupyutils.basic_cmds': {
        'windows': ['junctions', 'ntfs_streams', 'scandir'],
        'linux': ['xattr', 'scandir'],
        'all': [
            'pupyutils', 'scandir', 'zipfile',
            'tarfile', 'scandir', 'fsutils'
        ],
    },
    'dbus': {
        'linux': [
            '_dbus_bindings', 'pyexpat'
        ]
    },
    'sqlite3': {
        'all': ['_sqlite3'],
        'windows': ['sqlite3.dll'],
    },
    'xml': {
        'all': ['xml.etree']
    },
    'wql': {
        'windows': [
            'win32api', 'win32com', 'pythoncom',
            'winerror', 'wmi'
        ]
    },
    'secretstorage': {
        'linux': ['dbus']
    },
    'memorpy': {
        'windows': [
            'win32api',
            'win32security'
        ]
    },
    'scapy': {
        'windows': [
            'pythoncom',
        ]
    },
    'win32com': {
        'windows': [
            'pythoncom',
        ]
    },
    'pyaudio': {
        'all': [
            '_portaudio'
        ]
    },
    'OpenSSL': {
        'all': [
            'six',
            'enum',
            'cryptography',
            '_cffi_backend',
            'plistlib',
            'uu',
            'quopri',
            'pyparsing',
            'pkg_resources',
            'pprint',
            'ipaddress',
            'idna',
            'unicodedata',
        ]
    }
}

WELL_KNOWN_SHARED_DEPS = {
    'pythoncom': {
        'windows': [
            'pythoncom{pymaj}{pymin}.dll'
        ]
    },
    'pywintypes': {
        'windows': [
            'pywintypes{pymaj}{pymin}.dll'
        ]
    },
    'pythoncomloader': {
        'windows': [
            'pythoncomloader{pymaj}{pymin}.dll'
        ]
    }
}


logger.debug('LIBS_AUTHORIZED_PATHS=%s', LIBS_AUTHORIZED_PATHS)


def remove_dt_needed(data, libname):
    ef = ELFFile(data)
    dyn = ef.get_section_by_name('.dynamic')

    ent_size = dyn.header.sh_entsize
    sect_size = dyn.header.sh_size
    sect_offt = dyn.header.sh_offset

    tag_idx = None

    for idx in xrange(sect_size // ent_size):
        tag = dyn.get_tag(idx)
        if tag['d_tag'] == 'DT_NEEDED':
            if tag.needed == libname:
                tag_idx = idx
                break

    if tag_idx is None:
        return False

    null_tag = b'\x00' * ent_size
    dynamic_tail = None

    if idx == 0:
        dynamic_tail = dyn.data()[ent_size:] + null_tag
    else:
        dyndata = dyn.data()
        dynamic_tail = dyndata[:ent_size*(idx)] + \
            dyndata[ent_size*(idx+1):] + null_tag

    data.seek(sect_offt)
    data.write(dynamic_tail)
    return True


def safe_file_exists(f):
    """ some file systems like vmhgfs are case insensitive and
        os.isdir() return True for "lAzAgNE", so we need this check for modules
        like LaZagne.py and lazagne gets well imported """
    return os.path.basename(f) in os.listdir(os.path.dirname(f))


def bootstrap(target, stdlib, config, autostart=True):
    actions = [
        'from __future__ import absolute_import',
        'from __future__ import division',
        'from __future__ import print_function',
        'from __future__ import unicode_literals',

        'import {}, sys, marshal'.format(
            'types' if target.pymaj > 2 else 'imp'
          ),

        'stdlib = marshal.loads({stdlib})',
        'config = marshal.loads({config})',
        'pupy = {}("pupy")'.format(
            'types.ModuleType' if target.pymaj > 2 else 'imp.new_module'
        ),
        'pupy.__file__ = str("pupy://pupy/__init__.pyo")',
        'pupy.__package__ = str("pupy")',
        'pupy.__path__ = [str("pupy://pupy/")]',
        'sys.modules[str("pupy")] = pupy',

        'exec(marshal.loads(stdlib["pupy/__init__.pyo"][{}:]), pupy.__dict__)'.format(
            (4 * 4) if target.pymaj > 2 else (4 * 2)
        ),
    ]

    if autostart:
        actions.append('pupy.main(stdlib=stdlib, config=config)')
    else:
        actions.append('def main():')
        actions.append('    pupy.main(stdlib=stdlib, config=config)')

    loader = '\n'.join(actions)

    return loader.format(
        stdlib=reprb(marshal.dumps(stdlib, 2)),
        config=reprb(marshal.dumps(config, 2))
    )


def importer(
    target, dependencies, path=None,
        ignore_native=False, as_bundle=False, as_dict=False):

    if path:
        modules = {}
        if not type(dependencies) in (list, tuple, set, frozenset):
            dependencies = [dependencies]

        for dependency in dependencies:
            modules.update(from_path(target, path, dependency))

        if not as_dict:
            blob = pickle.dumps(modules, 2)
            blob = zlib.compress(blob, 9)
        else:
            blob = modules
    else:
        blob, modules, _ = package(
            target, dependencies,
            ignore_native=ignore_native, as_dict=as_dict
        )

    if as_bundle or as_dict:
        return blob
    else:
        return 'pupyimporter.pupy_add_package({}, compressed=True)'.format(
            reprb(blob))


def modify_native_content(target, filename, content):
    if not isinstance(content, bytes):
        return content

    if content.startswith(b'\x7fELF'):
        logger.info(
            'ELF file - %s, check for libpython DT_NEED record', filename
        )

        image = BytesIO(content)
        if remove_dt_needed(image, target.so):
            logger.info('Modified: DT_NEEDED %s removed', target.so)

        content = image.getvalue()

    return content


def get_py_encoding(content):
    lines = content[:1024].splitlines()
    if len(lines) < 1:
        return

    line = lines[0]
    if not (line.startswith(b'#') and
            b'coding:' in line):
        return

    idx = line.find(b'coding:') + 7
    end = line.find(b'-*-', idx)

    if end == -1:
        end = None

    coding = line[idx:end]
    return coding.decode('latin-1').strip()


def get_content(target, prefix, filepath, archive=None, honor_ignore=True):
    if filepath.startswith(prefix) and honor_ignore:
        basepath = filepath[len(prefix)+1:]
        basepath, ext = os.path.splitext(basepath)

        if ext in ('.pyo', 'py', '.pyc'):
            ext = '.py'

        basepath = basepath + ext

        arch_prefixes = ['all']
        arch_prefixes.append('all_py{}'.format(target.pymaj))

        if target.os:
            arch_prefixes.append(target.os)
            arch_prefixes.append(os.path.join(target.os, 'all'))

            if target.arch:
                arch_prefixes.append(os.path.join(target.os, target.arch))

        PATCHES_PATHS = [
            os.path.abspath(os.path.join(getcwd(), 'packages', 'patches')),
            os.path.abspath(os.path.join(ROOT, 'packages', 'patches')),
            os.path.abspath(os.path.join(ROOT, 'library_patches', 'py{}{}'.format(
                target.pymaj, target.pymin)))
        ]

        for patch_prefix in PATCHES_PATHS:
            if not os.path.isdir(patch_prefix):
                continue

            for arch_prefix in arch_prefixes:
                patch_dir = os.path.join(patch_prefix, arch_prefix)

                if not os.path.isdir(patch_dir):
                    continue

                maybe_patch = os.path.join(patch_dir, basepath)

                if os.path.exists(maybe_patch):
                    logger.info('Patch: %s -> %s', filepath, maybe_patch)
                    with open(maybe_patch, 'rb') as filedata:
                        return filedata.read()

                elif os.path.exists(maybe_patch+'.ignore'):
                    logger.info('Patch: Ignore %s', filepath)
                    raise IgnoreFileException()

                elif os.path.exists(maybe_patch+'.include'):
                    break

                else:
                    subpaths = basepath.split(os.path.sep)

                    for i in xrange(len(subpaths)):
                        ignore = [patch_dir] + subpaths[:i]
                        ignore.append('.ignore')
                        ignore = os.path.sep.join(ignore)
                        if os.path.exists(ignore):
                            logger.info(
                                'Patch: Ignore %s (%s)', filepath, ignore
                            )
                            raise IgnoreFileException()

    content = None

    if archive:
        content = archive.read(filepath)
    else:
        with open(filepath, 'rb') as filedata:
            content = filedata.read()

    if not target.native:
        logger.debug(
            'Modify natve content for %s (native=%s)',
            filepath, target.native
        )

        content = modify_native_content(target, filepath, content)

    return content


def from_path(
    target, search_path, start_path,
        remote=False, pure_python_only=False,
        honor_ignore=True, ignore_native=False):

    query = start_path

    modules_dic = {}

    if os.path.sep not in start_path:
        start_path = start_path.replace('.', os.path.sep)

    module_path = os.path.join(search_path, start_path)

    if remote:
        if '..' in module_path or not module_path.startswith(
                tuple(LIBS_AUTHORIZED_PATHS)):
            raise UnsafePathError(
                'Attempt to retrieve lib from unsafe '
                'path: {} (query={})'.format(
                    module_path, query
                )
            )

    # loading a real package with multiple files
    if os.path.isdir(module_path) and safe_file_exists(module_path):
        for root, dirs, files in os.walk(module_path, followlinks=True):
            for f in files:
                if root.endswith(IGNORED_ENDINGS) or f.startswith('.#'):
                    continue

                if f.endswith(('.so', '.pyd', '.dll')):
                    if pure_python_only:
                        if ignore_native:
                            continue

                        # avoid loosing shells when looking for packages in
                        # sys.path and unfortunatelly pushing a .so ELF on a
                        # remote windows
                        raise BinaryObjectError(
                            'Path contains binary objects: {} '
                            '(query={})'.format(f, query)
                        )

                if not f.endswith((
                        '.so', '.pyd', '.dll', '.pyo', '.pyc', '.py')):
                    continue

                try:
                    module_code = get_content(
                        target,
                        search_path,
                        os.path.join(root, f),
                        honor_ignore=honor_ignore
                    )
                except IgnoreFileException:
                    continue

                modprefix = root[len(search_path.rstrip(os.sep))+1:]
                modpath = os.path.join(modprefix, f).replace('\\', '/')

                base, ext = modpath.rsplit('.', 1)

                # Garbage removing
                if ext == 'py':
                    try:
                        module_code = pupycompile(
                            module_code, modpath, target=target.pyver
                        )
                        modpath = base+'.pyo'
                        if base+'.pyc' in modules_dic:
                            del modules_dic[base+'.pyc']
                    except Exception as e:
                        logger.error('Failed to compile %s: %s', modpath, e)

                elif ext == 'pyc':
                    if base+'.pyo' in modules_dic:
                        continue
                elif ext == 'pyo':
                    if base+'.pyo' in modules_dic:
                        continue
                    if base+'.pyc' in modules_dic:
                        del modules_dic[base+'.pyc']

                # Special case with pyd loaders
                elif ext == 'pyd':
                    if base+'.py' in modules_dic:
                        del modules_dic[base+'.py']

                    if base+'.pyc' in modules_dic:
                        del modules_dic[base+'.pyc']

                    if base+'.pyo' in modules_dic:
                        del modules_dic[base+'.pyo']

                if module_code is not None:
                    modules_dic[modpath] = module_code

    else:
        extlist = ['.py', '.pyo', '.pyc']
        if not pure_python_only:
            extlist.extend(('.so', '.pyd'))

            if target.pymaj == 2:
                extlist.append('27.dll')

        for ext in extlist:
            filepath = os.path.join(module_path+ext)
            if os.path.isfile(filepath) and safe_file_exists(filepath):
                try:
                    module_code = get_content(
                        target,
                        search_path,
                        filepath,
                        honor_ignore=honor_ignore,
                    )
                except IgnoreFileException:
                    break

                cur = ''
                for rep in start_path.split('/')[:-1]:
                    if cur + rep + ' /__init__.py' not in modules_dic:
                        modules_dic[rep+'/__init__.py'] = ''
                    cur += rep + '/'

                if ext == '.py':
                    module_code = pupycompile(
                        module_code, start_path+ext, target=target.pyver
                    )
                    ext = '.pyo'

                modules_dic[start_path+ext] = module_code

                break

    return modules_dic


def paths(target):
    """
    return the list of path to search packages for depending
    on client OS and architecture
    """

    posix = target.os != 'windows'

    path = [
        os.path.join('packages', target.os),
        os.path.abspath(os.path.join(ROOT, 'library_patches'))
    ]

    if target.arch:
        path = path + [
            os.path.join(p, target.arch) for p in path
        ]

    if posix:
        path.append(
            os.path.join('packages', 'posix')
        )

    path = path + [
        os.path.join(p, 'all') for p in path
    ]

    path.append(os.path.join('packages', 'all'))

    path = path + [
        os.path.join(ROOT, p) for p in path
    ]

    return [
        x for x in path if os.path.isdir(x)
    ]


def dependencies_for_target(target, module_name, rules):
    if module_name is not None:
        module_rules = rules.get(module_name, None)
    else:
        module_rules = rules

    if module_rules is None:
        return tuple()
    elif isinstance(module_rules, dict):
        pass
    else:
        return tuple(module_rules)

    py_suffixes = (':py{}'.format(target.pymaj), '')
    platforms = [
        target.os
    ]

    if target.os != 'windows':
        platforms.append('posix')

    options = tuple(
        platform + py_suffix
        for platform in platforms
        for py_suffix in py_suffixes
    )

    all_deps = []

    for py_suffix in py_suffixes:
        all_deps.extend(module_rules.get('all' + py_suffix, []))

    for option in options:
        deps = module_rules.get(option, None)
        if deps is not None:
            all_deps.extend(deps)

    return tuple(
        dep.format(
            pymaj=target.pymaj,
            pymin=target.pymin,
            os=target.os
        ) for dep in all_deps
    )


def _dependencies(target, module_name, dependencies):
    logger.info('Add dep %s', module_name)
    dependencies.add(module_name)

    shared_deps = dependencies_for_target(
        target, module_name, WELL_KNOWN_SHARED_DEPS
    )

    if shared_deps:
        logger.info('Add shared deps for %s: %s', module_name, shared_deps)
        dependencies.update(shared_deps)

    py_deps = dependencies_for_target(
        target, module_name, WELL_KNOWN_DEPS
    )

    if not py_deps:
        return

    logger.info('Add deps for %s: %s', module_name, py_deps)
    dependencies.update(py_deps)

    for dep in py_deps:
        _dependencies(target, dep, dependencies)

    logger.info('Add deps for %s: %s (child deps) - complete', module_name, py_deps)


def _package(
    target, modules, module_name, remote=False,
        honor_ignore=True, ignore_native=False):

    initial_module_name = module_name

    start_path = module_name.replace('.', os.path.sep)

    for search_path in paths(target):
        modules_dic = from_path(
            target, search_path, start_path,
            remote=remote, honor_ignore=honor_ignore
        )

        if modules_dic:
            break

    if not modules_dic:
        archive = bundle(target)
        if archive:
            modules_dic = {}

            endings = list(COMMON_MODULE_ENDINGS)

            try:
                extension_suffix = [
                    x.strip() for x in archive.open(
                        'extension-suffix'
                    ).read().decode('ascii').split('\n')
                ]

                endings.extend([
                    ( '.' + ext if not ext.startswith('.') else '' )
                    for ext in extension_suffix
                ])

            except (KeyError, StopIteration):
                # No extension-suffix, okay..
                if target.os == 'windows':
                    extension_suffix = '.pyd'
                else:  # Well, better than nothing
                    extension_suffix = '.so'

            # Special case for windows
            if target.os == 'windows':
                extension_suffix.append('.dll')

            start_paths = tuple([
                (
                    '/'.join([x, start_path])
                ).strip('/') + y
                for x in COMMON_SEARCH_PREFIXES
                for y in endings
            ])

            for info in archive.infolist():
                content = None
                if not info.filename.startswith(start_paths):
                    if initial_module_name in info.filename:
                        logger.info('%s: omit %s', initial_module_name, info.filename)
                    continue

                logger.info('%s: try %s', initial_module_name, info.filename)

                module_name = info.filename

                for prefix in COMMON_SEARCH_PREFIXES:
                    if module_name.startswith(prefix + '/'):
                        module_name = module_name[len(prefix)+1:]
                        break

                module_name_ending = None

                for ending in endings:
                    if '.' not in ending:
                        logger.info(
                            '%s: omit %s: invalid ending: %s',
                            initial_module_name, info.filename, ending
                        )
                        continue

                    if module_name.endswith(ending):
                        if not module_name_ending or \
                          len(ending) > len(module_name_ending):
                            module_name_ending = ending

                if not module_name_ending:
                    logger.info(
                        '%s: omit %s: no valid ending found in %s',
                        initial_module_name, info.filename, endings
                    )
                    continue

                base = module_name[:-len(module_name_ending)]
                ext = module_name_ending.rsplit('.', 1)[-1]

                # Garbage removing
                if ext == 'py':
                    try:
                        content = get_content(
                            target, prefix,
                            info.filename, archive,
                            honor_ignore=honor_ignore
                        )

                        try:
                            content = pupycompile(
                                content,
                                info.filename,
                                target=target.pyver
                            )

                            ext = 'pyo'

                            if base+'.py' in modules_dic:
                                del modules_dic[base+'.py']

                            if base+'.pyc' in modules_dic:
                                del modules_dic[base+'.pyc']

                        except ValueError as e:
                            logger.error(
                                'Failed to compile %s: %s',
                                info.filename, e
                            )

                    except IgnoreFileException:
                        logger.info(
                            'Failed to get content for %s: IgnoreFileException',
                            info.filename
                        )
                        continue

                elif ext == 'pyc':
                    if base+'.py' in modules_dic:
                        del modules_dic[base+'.py']

                    if base+'.pyo' in modules_dic:
                        continue
                elif ext == 'pyo':
                    if base+'.py' in modules_dic:
                        del modules_dic[base+'.py']

                    if base+'.pyc' in modules_dic:
                        del modules_dic[base+'.pyc']

                    if base+'.pyo' in modules_dic:
                        continue
                # Special case with pyd loaders
                elif ext == 'pyd':
                    if base+'.py' in modules_dic:
                        del modules_dic[base+'.py']

                    if base+'.pyc' in modules_dic:
                        del modules_dic[base+'.pyc']

                    if base+'.pyo' in modules_dic:
                        del modules_dic[base+'.pyo']

                if not content:
                    try:
                        content = get_content(
                            target, prefix,
                            info.filename, archive,
                            honor_ignore=honor_ignore
                        )
                    except IgnoreFileException:
                        logger.info(
                            'Failed to get content for %s: IgnoreFileException',
                            info.filename
                        )
                        continue

                if content:
                    logger.info(
                        '%s: loaded from %s',
                        initial_module_name, info.filename
                    )
                    modules_dic[base+'.'+ext] = content

            archive.close()

    # in last resort, attempt to load the package from the
    # server's sys.path if it exists

    if not modules_dic:
        for search_path in sys.path:
            try:
                modules_dic = from_path(
                    target, search_path, start_path,
                    pure_python_only=True, ignore_native=ignore_native,
                    remote=remote
                )

                if modules_dic:
                    logger.info(
                        'package %s not found in packages/, but found in'
                        'local sys.path attempting to push it remotely',
                        initial_module_name
                    )
                    break

            except BinaryObjectError as e:
                logger.warning(e)

            except UnsafePathError as e:
                logger.error(e)

    if not modules_dic:
        raise NotFoundError(initial_module_name)

    modules.update(modules_dic)


def package(
    target, requirements, remote=False, filter_needed_cb=None,
        honor_ignore=True, ignore_native=False, as_dict=False):

    dependencies = set()

    if not type(requirements) in (list, tuple, set, frozenset):
        requirements = [requirements]

    for requirement in requirements:
        _dependencies(target, requirement, dependencies)

    package_deps = set()
    dll_deps = set()

    for dependency in dependencies:
        if dependency.endswith(('.so', '.dll')):
            dll_deps.add(dependency)
        else:
            package_deps.add(dependency)

    if filter_needed_cb:
        if package_deps:
            package_deps = filter_needed_cb(package_deps, False)

        if dll_deps:
            dll_deps = filter_needed_cb(dll_deps, True)

    payload = b''
    contents = []
    dlls = []

    if package_deps:
        modules = {}

        for dependency in package_deps:
            _package(
                target, modules, dependency,
                remote=remote, honor_ignore=honor_ignore,
                ignore_native=ignore_native
            )

        if not as_dict:
            payload = zlib.compress(
                pickle.dumps(modules, 2), 9
            )
        else:
            payload = modules

        contents = list(dependencies)

    if dll_deps:
        for dependency in dll_deps:
            dlls.append((dependency, dll(target, dependency)))

    return payload, contents, dlls


def bundle(target):
    if not target.os or not target.arch:
        return None

    bundle_name = '{}-{}-{}{}.zip'.format(
        target.os, target.arch, target.pymaj, target.pymin
    )

    arch_bundle = os.path.join(
        'payload_templates', bundle_name
    )

    if not os.path.isfile(arch_bundle):
        arch_bundle = os.path.join(
            ROOT, 'payload_templates', bundle_name
        )

    if not os.path.exists(arch_bundle):
        return None

    return ZipFile(arch_bundle, 'r')


def dll(target, name, honor_ignore=True):
    buf = b''

    for packages_path in paths(target):
        dll_path = os.path.join(packages_path, name)
        if os.path.exists(dll_path):
            try:
                buf = get_content(
                    target, name, dll_path,
                    honor_ignore=honor_ignore
                )
            except IgnoreFileException:
                pass

            break

    if not buf:
        archive = bundle(target)
        if archive:
            for info in archive.infolist():
                if info.filename.endswith('/'+name) or info.filename == name:
                    try:
                        buf = get_content(
                            target, os.path.dirname(info.filename),
                            info.filename,
                            archive,
                            honor_ignore=honor_ignore
                        )
                    except IgnoreFileException:
                        pass

                    break

            archive.close()

    if not buf:
        raise NotFoundError(name)

    return buf
