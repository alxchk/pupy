#ifndef PYTHON_DYNLOAD_COMPAT_H
#define PYTHON_DYNLOAD_COMPAT_H

typedef void* (*initfunc_t)();

PyObject* PyOpen(int fd, const char *name, const char *mode, int buf);
PyObject* PyInit_Module(PyObject *spec, const char *modname, initfunc_t initfunc);

#endif
