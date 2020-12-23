from __future__ import print_function
from __future__ import unicode_literals

# A script to generate helper files for dynamic linking to the Python dll
#

import string
import sys

from io import open

UCS_ABI = 'UCS4'
PY_ABI = 2
PY_REV = 7

if len(sys.argv) > 1:
    UCS_ABI = sys.argv[1]

if len(sys.argv) > 2:
    PY_ABI = int(sys.argv[2])

if len(sys.argv) > 3:
    PY_REV = int(sys.argv[3])

if PY_ABI == 3 and PY_REV != 8:
    sys.exit('Python 3.8 is only supported interpeter')

mappings = {}

if PY_ABI > 2:
    mappings.update({
        'PyString_AsString': 'PyUnicode_AsUTF8',
        'PyString_AsStringAndSize': 'PyUnicode_AsUTF8AndSize',
        'PyString_FromString': 'PyUnicode_FromString',
        'PyString_FromFormat': 'PyUnicode_FromFormat',
        'PyString_FromStringAndSize': 'PyUnicode_FromStringAndSize',
        'PyInt_FromLong': 'PyLong_FromLong',
        'PyInt_AsLong': 'PyLong_AsLong',
        'PyInt_Type': 'PyLong_Type'
    })

else:
    mappings.update({
        'PyBytes_FromStringAndSize': 'PyString_FromStringAndSize',
        'PyBytes_FromString': 'PyString_FromString',
        'PyBytes_AsStringAndSize': 'PyString_AsStringAndSize',
        'PyBytes_AsString': 'PyString_AsString',
        'PyUnicode_AsWideChar': (
            'PyUnicode' + UCS_ABI + '_AsWideChar'
        ),
        'PyUnicode_GetSize': (
            'PyUnicode' + UCS_ABI + '_GetSize'
        )
    })


decls = '''
void, Py_InitializeEx, (int)
void, Py_Finalize, (void)
PyObject *, PyMarshal_ReadObjectFromString, (const char *, Py_ssize_t)
int, PyBytes_AsStringAndSize, (PyObject *, const char **, Py_ssize_t *)
const char *, PyBytes_AsString, (PyObject *)
int, PyArg_ParseTuple, (PyObject *, const char *, ...)
int, PyArg_ParseTupleAndKeywords, (PyObject *args, PyObject *kw, const char *format, const char * const *keywords, ...)
PyObject *, PyImport_ImportModule, (const char *)
PyObject *, PyInt_FromLong, (long)
long, PyInt_AsLong, (PyObject *)
PyObject *, PyLong_FromVoidPtr, (void *)
int, Py_IsInitialized, (void)
int, PyObject_SetAttrString, (PyObject *, const char *, PyObject *)
void*, PyUnicode_AsWideChar, (PyObject *o, wchar_t *w, Py_ssize_t size)
Py_ssize_t, PyUnicode_GetSize, (PyObject *unicode)
PyObject *, PyCFunction_NewEx, (PyMethodDef *, PyObject *, PyObject *)
PyObject *, PyObject_GetAttrString, (PyObject *, const char *)
PyObject *, Py_BuildValue, (const char *, ...)
PyObject *, PyObject_Call, (PyObject *, PyObject *, PyObject *)
PyObject *, PyObject_CallFunctionObjArgs, (PyObject *, ...)
PyObject *, PyObject_CallFunction, (PyObject *, const char *, ...)
PyObject *, PyErr_Occurred, (void)
void, PyErr_Fetch, (PyObject **, PyObject **, PyObject **)
void, PyErr_Clear, (void)
PyObject*, PyErr_NoMemory, (void)
int, PyObject_IsInstance, (PyObject *, PyObject *)
PyObject *, PyCapsule_New, (void *, const char *, void *)
void *, PyCapsule_GetPointer, (PyObject *, const char *)

void, Py_IncRef, (PyObject *)
void, Py_DecRef, (PyObject *)

PyObject, PyUnicode_Type
PyObject, _Py_NoneStruct

PyObject*, PyErr_SetFromErrno, (PyObject *)
PyObject*, PyErr_Format, (PyObject *, const char *format, ...)

PyObject *, PyExc_ImportError
PyObject *, PyExc_Exception
PyObject *, PyExc_KeyError
PyObject *, PyExc_OSError
const char *, _Py_PackageContext

int, Py_NoSiteFlag
int, Py_OptimizeFlag
int, Py_NoUserSiteDirectory
int, Py_DontWriteBytecodeFlag
int, Py_IgnoreEnvironmentFlag

PyObject *, PyObject_CallObject, (PyObject *, PyObject *)

PyGILState_STATE, PyGILState_Ensure, (void)
void, PyGILState_Release, (PyGILState_STATE)

void, PySys_SetObject, (const char *, PyObject *)
PyObject *, PySys_GetObject, (const char *)
PyObject *, PyBytes_FromString, (const char *)
PyObject *, PyImport_AddModule, (const char *)
PyObject*, PyImport_ExecCodeModuleEx, (char *name, PyObject *co, char *pathname)
PyObject *, PyModule_GetDict, (PyObject *)
int, PyDict_Next, (PyObject *, Py_ssize_t *, PyObject **, PyObject **)
PyObject*, PyDict_Keys, (PyObject *)
void, PyDict_Clear, (PyObject *)
Py_ssize_t, PySequence_Length, (PyObject *)
PyObject *, PySequence_GetItem, (PyObject *, Py_ssize_t)
PyObject *, PyEval_EvalCode, (PyObject *, PyObject *, PyObject *)
PyObject *, PyEval_GetBuiltins, ()
void, PyErr_Print, (void)
PyObject *, PyBool_FromLong, (long)
const char *, Py_FileSystemDefaultEncoding
PyObject*, PyList_New, (Py_ssize_t)
PyObject*, PyList_GetItem, (PyObject *, Py_ssize_t)
PyObject*, PyList_Append, (PyObject *, PyObject *)
int, PyList_SetSlice, (PyObject *list, Py_ssize_t low, Py_ssize_t high, PyObject *itemlist)
Py_ssize_t, PyList_Size, (PyObject *list)
int, PyObject_IsTrue, (PyObject *)
PyObject*, PyObject_GetIter, (PyObject *)
PyObject*, PyIter_Next, (PyObject *o)
void, PyErr_SetString, (PyObject *, const char *)
void, PyEval_InitThreads, (void)

PyObject *, PyErr_NewException, (const char *name, PyObject *base, PyObject *dict)
int, PyModule_AddObject, (PyObject *, const char *, PyObject *)
int, PyModule_AddStringConstant, (PyObject *module, const char *name, const char *value)

PyObject*, PyDict_New, ()
PyObject*, PyBytes_FromStringAndSize, (const char *v, Py_ssize_t len)
int, PyDict_Update, (PyObject *a, PyObject *b)
int, PyDict_SetItem, (PyObject *p, PyObject *key, PyObject *val)
int, PyDict_SetItemString, (PyObject *, const char *, PyObject *)
int, PyDict_DelItem, (PyObject *a, PyObject *b)
PyObject*, PyDict_GetItemString, (PyObject *p, const char *key)
int, PyDict_DelItemString, (PyObject *p, const char *key)

int, PyImport_AppendInittab, (const char *, void*)
'''.strip().splitlines()

if PY_ABI == 2:
    decls.extend([
        'PyObject *, PyFile_FromFile, (FILE *fp, char *name, char *mode, int (*close)(FILE*))',
        'void, PyFile_SetBufSize, (PyObject *, int)',
        'char *, Py_GetPath, (void)',
        'void, Py_SetPythonHome, (const char *)',
        'void, Py_SetProgramName, (const char *)',
        'PyObject, PyString_Type',
        'PyObject *, Py_InitModule4, (const char *, PyMethodDef *, const char *, PyObject *, int)',
    ])
else:
    decls.extend([
        'const struct _frozen *, PyImport_FrozenModules',
        'PyObject *, PyImport_GetModuleDict, ()',
        'PyObject *, PyModule_FromDefAndSpec2, (PyObject*, PyObject*, int)',
        'PyObject, PyModuleDef_Type',
        'int, _PyImport_FixupExtensionObject, (PyObject*, PyObject*, PyObject*, PyObject*)',

        'PyObject *, PyString_FromString, (const char *)',
        'PyObject*, PyString_FromStringAndSize, (const char *v, Py_ssize_t len)',
        'int, PyString_AsStringAndSize, (PyObject *, const char **, Py_ssize_t *)',
        'const char *, PyString_AsString, (PyObject *)',

        'PyObject *, PyUnicode_FromFormat, (const char *, ...)',
        'PyObject*, PyFile_FromFd, (int fd, const char *name, const char *mode, int buffering, '
            'const char *encoding, const char *errors, const char *newline, int closefd)',
        'wchar_t *, Py_DecodeLocale, (const char *, size_t *)',
        'wchar_t *, Py_GetPath, (void)',
        'void, Py_SetPythonHome, (const wchar_t *)',
        'void, Py_SetProgramName, (const wchar_t *)',
        'void, PyMem_RawFree, (void*)',
        'PyObject*, PyModule_Create2, (PyModuleDef *, int)',

        'PyObject, PyBytes_Type',
])

hfile = open("import-tab.h", "w")
cfile = open("import-tab.c", "w")

index = 0

for decl in decls:
    if not decl or decl.startswith("//"):
        continue

    items = decl.split(',', 2)

    if len(items) == 3:
        # exported function with argument list
        restype, name, argtypes = map(lambda x: x.strip(), items)
        print('#define %(name)s ((%(restype)s(*)%(argtypes)s)py_sym_table[%(index)d].proc)' % locals(
        ), file=hfile)
    elif len(items) == 2:
        # exported data
        typ, name = map(lambda x: x.strip(), items)
        print('#define %(name)s (*(%(typ)s(*))py_sym_table[%(index)s].proc)' % locals(
        ), file=hfile)
    else:
        raise ValueError("could not parse %r" % decl)

    if name == "Py_InitModule4":
        print('#ifdef _DEBUG', file=cfile)
        print('\t{ "Py_InitModule4TraceRefs", NULL },' % locals(), file=cfile)
        print('#else', file=cfile)
        print('#  if defined (__x86_64__) || defined (_WIN64)', file=cfile)
        print('\t{ "Py_InitModule4_64", NULL },' % locals(), file=cfile)
        print('#  else', file=cfile)
        print('\t{ "Py_InitModule4", NULL },' % locals(), file=cfile)
        print('#  endif', file=cfile)
        print('#endif', file=cfile)
    elif name in mappings:
        print('\t{ "%s", NULL },' % mappings[name], file=cfile)
    else:
        print('\t{ "%(name)s", NULL },' % locals(), file=cfile)

    index += 1

if PY_ABI == 2:
    print('#define PyString_FromStringAndSize PyBytes_FromStringAndSize', file=hfile);
    print('#define PyString_AsStringAndSize PyBytes_AsStringAndSize', file=hfile);
    print('#define PyString_AsString PyBytes_AsString', file=hfile);
    print('#define PyString_FromString PyBytes_FromString', file=hfile);

hfile.close()
cfile.close()
