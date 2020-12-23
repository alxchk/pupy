#if PYMAJ > 2
#define PyModuleDef_Check(op) PyObject_IsInstance(op, &PyModuleDef_Type)

PyObject *PyOpen(int fd, const char *name, const char *mode, int buf) {
    return PyFile_FromFd(fd, name, mode, buf, NULL, NULL, NULL, 1);
}

#else
PyObject *PyOpen(int fd, const char *name, const char *mode, int buf) {
    PyObject * result;
    FILE *file = fdopen(fd, mode);

    if (!file)
        return NULL;

    result = PyFile_FromFile(fd, name, mode, fclose);
    if (buf != -1 && result)
        PyFile_SetBufSize(result, buf);

    return result;
}
#endif

PyObject* PyInit_Module(PyObject *spec, const char *modname, initfunc_t initfunc)
{
    const char *oldcontext;
    PyObject *result = NULL;

#if PYMAJ > 2
    PyObject *module = NULL;
#endif

    oldcontext = _Py_PackageContext;
    _Py_PackageContext = modname;
    dprint("PyInit_Module %s (%p)\n", modname, initfunc);

#if PYMAJ > 2
    module = initfunc();
    if (module) {
        if (PyModuleDef_Check(module)) {
            dprint("PyInit_Module %s (%p): new moduledef: %p\n", modname, initfunc, module);
            result = PyModule_FromDefAndSpec2(module, spec, 3);
            if (result) {
                PyObject *modules = PyImport_GetModuleDict();
                if (PyDict_SetItemString(modules, modname, result) < 0)
                    result = NULL;
            }
        } else {
            PyObject *modules = PyImport_GetModuleDict();
            PyObject *name_unicode = PyObject_GetAttrString(spec, "name");
            PyObject *path = PyObject_GetAttrString(spec, "origin");

            dprint("PyInit_Module %s (%p): single-phase init: %p\n", modname, initfunc, module);

            if (PyModule_AddObject(module, "__file__", path) < 0) {
                PyErr_Clear(); /* Not important enough to report */
            } else {
                Py_IncRef(path);
            }

            if (_PyImport_FixupExtensionObject(module, name_unicode, path, modules) < 0) {
                result = NULL;
            } else {
                result = module;
            }

            Py_DecRef(name_unicode);
            Py_DecRef(path);
        }
    } else {
        PyErr_Format(
            PyExc_ImportError,
            "Could initialize module %s", modname
        );

        result = NULL;
    }
#else
    initfunc();
    result = PyImport_ImportModule(modname);
#endif

    _Py_PackageContext = oldcontext;

    dprint("PyInit_Module %s (%p) - complete -> %p\n", modname, initfunc, result);

    return result;
}
