#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function
from __future__ import unicode_literals

import sys
import binascii
import pylzma
import struct
import os

from io import open

MAX_CHAR_PER_LINE = 50

ReflectiveLoaderSymName = 'ReflectiveLoader'

ZERO_STRINGS = [
    b'Software\\Python\\PythonCore'
]

ZERO_STRINGS.extend([
    z.decode('ascii').encode('utf-16le') for z in ZERO_STRINGS
])


if __name__ == "__main__":
    h_file = ""
    file_bytes = b""
    output = os.path.basename(sys.argv[2]).replace('.', '_')

    reflective_loader = None

    with open(sys.argv[1], "rb") as f:
        file_bytes = f.read()
        for z in ZERO_STRINGS:
            if z in file_bytes:
                file_bytes = file_bytes.replace(z, b'\00' * len(z))

    try:
        image_base = 0

        with open(sys.argv[1]+'.map') as f:
            for line in f:
                line = line.strip().split()

                if len(line) < 4:
                    continue

                if line[1] == '__ImageBase':
                    image_base = int(line[2], 16)
                    continue

                if line[1] in (ReflectiveLoaderSymName, '_' + ReflectiveLoaderSymName + '@4'):
                    reflective_loader = int(line[2], 16) - image_base
                    break

    except (OSError, IOError):
        pass

    compressed = int(sys.argv[3])

    attribute = ''
    pragma = ''

    if len(sys.argv) > 5:
        compiler = sys.argv[4]

        if compiler == 'cl':
            print("USING MSVC pragmas, const_seg: {}".format(sys.argv[5]))
            attribute = '\n#pragma const_seg(push, stack1, "{}")\n'.format(
                sys.argv[5])
            pragma = '\n#pragma const_seg(pop, stack1)'
        else:
            attribute = '\n'.join([
                '__attribute__(({}))'.format(x) for x in sys.argv[5:]
            ])

    payload_len = len(file_bytes)
    payload = struct.pack('>I', payload_len) + (
        pylzma.compress(
            file_bytes, dictionary=24, fastBytes=255
        ) if compressed else file_bytes
    )

    if reflective_loader:
        h_file += "static const size_t %s_loader = 0x%x;\n" % (
            output, reflective_loader)

        with open(sys.argv[2].rsplit('.', 1)[0] + '.loader', 'w+b') as w:
            w.write(struct.pack('>I', reflective_loader))

    h_file += "static const int %s_size = %s;" % (output, len(payload))
    h_file += attribute
    h_file += "\nstatic const char %s_start[] = {\n" % (output)

    current_size = 0

    with open(sys.argv[2], 'w') as w:
        w.write(h_file)

        for c in payload:
            if isinstance(c, int):
                w.write("'\\x%02x'," % (c))
            else:
                w.write("'\\x%s'," % binascii.hexlify(c))

            current_size += 1
            if current_size > MAX_CHAR_PER_LINE:
                current_size = 0
                w.write("\n")

        w.write("'\\x00' };\n")
        w.write(pragma)
