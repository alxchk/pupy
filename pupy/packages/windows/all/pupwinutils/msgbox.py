#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import ctypes
import threading

from network.lib.convcompat import as_unicode_string


def MessageBox(text, title):
    text = as_unicode_string(text, fail=False)
    title = as_unicode_string(title, fail=False)

    t = threading.Thread(
        target=ctypes.windll.user32.MessageBoxW, args=(
            None, text, title, 0
        )
    )

    t.daemon=True
    t.start()
