# -*- encoding: utf-8 -*-

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import adodbapi
import sys
import datetime

from network.lib.convcompat import fs_as_unicode_string

PROVIDER = 'provider=Search.CollatorDSO.1;EXTENDED?PROPERTIES="Application=Windows"'


def query(sql, limit):
    data = []
    error = None
    idx = 0
    cidx = 0

    conn = adodbapi.connect(PROVIDER)

    try:
        cursor = conn.cursor()
        cursor.execute(sql)
        for idx, record in enumerate(cursor):

            if idx >= limit:
                break

            line = []

            for cidx, column in enumerate(record):
                if isinstance(column, bytes):
                    column = fs_as_unicode_string(column)
                elif type(column) == datetime.datetime:
                    column = int((
                        column - datetime.datetime.utcfromtimestamp(0)
                    ).total_seconds())
                line.append(column)

            data.append(tuple(line))

    except adodbapi.apibase.DatabaseError as e:
        # ZOMG
        if hasattr(e, 'message'):
            parts = e.message.split('\n')
        else:
            parts = str(e).split('\n')

        code = fs_as_unicode_string(eval(parts[0])[1])
        error = '\n'.join(parts[1:]) + '\n' + code

    finally:
        conn.close()

    return idx, cidx, data, error
