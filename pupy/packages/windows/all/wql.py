# -*- encoding: utf-8 -*-

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import wmi

from network.lib.convcompat import try_as_unicode_string


def execute(query):
    try:
        client = wmi.WMI(namespace="root\\cimv2")
    except wmi.x_wmi_uninitialised_thread:
        import pythoncom
        pythoncom.CoInitialize()
        client = wmi.WMI(namespace="root\\cimv2")

    return client.query(query)


def execute_final(query):
    response = execute(query)

    columns = set()
    result = []

    for item in response:
        columns.update(item.properties)

        result.append(
            tuple(
                (
                    try_as_unicode_string(column),
                    try_as_unicode_string(getattr(item, column))
                ) for column in item.properties
            )
        )

    _query = query.lower()
    try:
        idx_select = _query.index('select') + 7
        idx_from = _query.index('from')

        fields = try_as_unicode_string(query[idx_select:idx_from])
        if '*' not in fields:
            maybe_columns = tuple(x.strip() for x in fields.split(','))
            if all(column in columns for column in maybe_columns):
                columns = maybe_columns

    except ValueError:
        pass

    return tuple(columns), tuple(result)
