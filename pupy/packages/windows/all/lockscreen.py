# -*- encoding: utf-8 -*-

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

from ctypes import WinDLL, c_bool

user32 = WinDLL('user32')

LockWorkStation = user32.LockWorkStation
LockWorkStation.retval = c_bool


def lock():
    return LockWorkStation()
