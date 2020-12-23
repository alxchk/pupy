# -*- coding: utf-8 -*-

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import sys

from network.lib.convcompat import as_unicode_string_deep


def to_strings_list(function, *args, **kwargs):
    results = []
    raise_on_exception = kwargs.pop('raise_on_exception', True)

    iterator = function(*args, **kwargs)

    while True:
        try:
            result = next(iterator)
            results.append(
                as_unicode_string_deep(result, fail='convert')
            )

        except StopIteration:
            break

        except:
            if raise_on_exception:
                raise

    return results
