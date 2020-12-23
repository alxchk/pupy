/*
    WARNING !
    DEPENDS ON PYTHON ABI!
*/

#ifndef PYTHON_DYNLOAD_H
#define PYTHON_DYNLOAD_H

#if PYMAJ > 3
#error FIXME: Fix PYMAJ/PYMIN checks
#endif

#if (PYMAJ > 2 && PYMIN > 8)
#error Python > 3.8 is not supported
#endif

#include <stdint.h>
#include <string.h>
#include <wchar.h>
#include <sys/types.h>

#define CO_MAXBLOCKS 20

typedef uintptr_t Py_uintptr_t;
typedef intptr_t Py_intptr_t;

typedef long int Py_ssize_t;

typedef struct _object {
    Py_ssize_t ob_refcnt;
    struct _typeobject *ob_type;
} PyObject;

typedef struct {
    PyObject ob_base;
    Py_ssize_t ob_size; /* Number of items in variable part */
} PyVarObject;

#define PyObject_HEAD PyObject ob_base;
#define PyObject_VAR_HEAD PyVarObject ob_base;

#define Py_REFCNT(ob)           (((PyObject*)(ob))->ob_refcnt)
#define Py_TYPE(ob)             (((PyObject*)(ob))->ob_type)
#define Py_SIZE(ob)             (((PyVarObject*)(ob))->ob_size)

typedef struct {
    int b_type;
    int b_handler;
    int b_level;
} PyTryBlock;

typedef PyObject *(*PyCFunction)(PyObject *, PyObject *);

typedef
    enum {PyGILState_LOCKED, PyGILState_UNLOCKED}
        PyGILState_STATE;

typedef struct {
    char *ml_name;
    PyCFunction ml_meth;
    int ml_flags;
    char *ml_doc;
} PyMethodDef;

struct py_imports {
    char *name;
    void (*proc)();
};

#if defined(_MSC_VER)
#ifdef _WIN64
    #define ssize_t signed long long
#else
    #define ssize_t signed long
#endif
#endif

#ifndef Py_ssize_t
    #define Py_ssize_t ssize_t
#endif

#ifndef BOOL
    typedef int BOOL;
    #define TRUE 1
    #define FALSE 0
#endif

#ifndef Py_INCREF
    #define Py_INCREF Py_IncRef
#endif

#ifndef Py_DECREF
    #define Py_DECREF Py_DecRef
#endif

#ifndef Py_XINCREF
    #define Py_XINCREF(op) do { if ((op) == NULL) ; else Py_INCREF(op); } while (0)
#endif

#ifndef Py_XDECREF
    #define Py_XDECREF(op) do { if ((op) == NULL) ; else Py_DECREF(op); } while (0)
#endif

#if defined(_WIN32) && defined(_MSC_VER) && _MSC_VER < 1600
    #define snprintf _snprintf
#endif

#define METH_OLDARGS  0x0000
#define METH_VARARGS  0x0001
#define METH_KEYWORDS 0x0002
/* METH_NOARGS and METH_O must not be combined with the flags above. */
#define METH_NOARGS   0x0004
#define METH_O        0x0008

/* METH_CLASS and METH_STATIC are a little different; these control
   the construction of methods for a class.  These cannot be used for
   functions in modules. */
#define METH_CLASS    0x0010
#define METH_STATIC   0x0020

#define PyCFunction_New(ML, SELF) PyCFunction_NewEx((ML), (SELF), NULL)

#define PyInt_Check(op) PyObject_IsInstance(op, &PyInt_Type)
#define PyUnicode_Check(op) PyObject_IsInstance(op, &PyUnicode_Type)
#if PYMAJ > 2
#define PyBytes_Check(op) PyObject_IsInstance(op, &PyBytes_Type)
#else
#define PyBytes_Check(op) PyObject_IsInstance(op, &PyString_Type)
#endif

#define Py_None (&_Py_NoneStruct)

#define DL_EXPORT(x) x

#define PYTHON_API_VERSION 1013

#define Py_InitModule3(name, methods, doc) \
       Py_InitModule4(name, methods, doc, (PyObject *)NULL, \
                      PYTHON_API_VERSION)

#define PyModule_Create(def) PyModule_Create2(def, PYMAJ)

int Py_RefCnt(const PyObject *object);

extern struct py_imports py_sym_table[];

#if PYMAJ > 2
typedef PyObject* (*pupy_init_t)(void);
#else
typedef void* (pupy_init_t) (void);
#endif

BOOL initialize_python(
    int argc, char *argv[], BOOL is_shared_object,
    pupy_init_t *init
);
void run_pupy(void);
void deinitialize_python(void);

#define VPATH_PREFIX "pupy://"
#define VPATH_EXT ".pyo"
#define VPATH_INIT_EXT "/__init__" VPATH_EXT

#define ENCODINGS "encodings"


typedef struct {
    PyObject_HEAD

    int co_argcount;
#if PYMAJ > 2
#if PYMIN > 7
    int co_posonlyargcount;     /* #positional only arguments */
#endif
    int co_kwonlyargcount;      /* #keyword only arguments */
#endif
    int co_nlocals;
    int co_stacksize;
    int co_flags;

#if PYMAJ > 2 && PYMIN > 5
    int co_firstlineno;         /* first source line number */
#endif

    PyObject *co_code;
    PyObject *co_consts;
    PyObject *co_names;
    PyObject *co_varnames;
    PyObject *co_freevars;
    PyObject *co_cellvars;

#if PYMAJ > 2
    Py_ssize_t *co_cell2arg;    /* Maps cell vars which are arguments. */
#endif

    PyObject *co_filename;
    PyObject *co_name;

#if PYMAJ < 3 || (PYMAJ == 3 && PYMIN < 5)
    int co_firstlineno;
#endif
    PyObject *co_lnotab;
    void *co_zombieframe;
    PyObject *co_weakreflist;
} PyCodeObject;

typedef struct _is {

    struct _is *next;
    struct _ts *tstate_head;

    /* PRIVATE PART OMITTED */

} PyInterpreterState;

struct _frame;

#if PYMAJ > 2

typedef struct {
    enum {
        _PyStatus_TYPE_OK=0,
        _PyStatus_TYPE_ERROR=1,
        _PyStatus_TYPE_EXIT=2
    } _type;
    const char *func;
    const char *err_msg;
    int exitcode;
} PyStatus;

/* --- PyConfig ---------------------------------------------- */

#if PYMIN == 8

typedef struct {
    Py_ssize_t argc;
    int use_bytes_argv;
    char * const *bytes_argv;
    wchar_t * const *wchar_argv;
} _PyArgv;

typedef struct {
    /* If length is greater than zero, items must be non-NULL
       and all items strings must be non-NULL */
    Py_ssize_t length;
    wchar_t **items;
} PyWideStringList;

typedef struct {
    int _config_init;     /* _PyConfigInitEnum value */

    int isolated;         /* Isolated mode? see PyPreConfig.isolated */
    int use_environment;  /* Use environment variables? see PyPreConfig.use_environment */
    int dev_mode;         /* Development mode? See PyPreConfig.dev_mode */
    int install_signal_handlers;
    int use_hash_seed;      /* PYTHONHASHSEED=x */
    unsigned long hash_seed;
    int faulthandler;
    int tracemalloc;

    int import_time;        /* PYTHONPROFILEIMPORTTIME, -X importtime */
    int show_ref_count;     /* -X showrefcount */
    int show_alloc_count;   /* -X showalloccount */
    int dump_refs;          /* PYTHONDUMPREFS */
    int malloc_stats;       /* PYTHONMALLOCSTATS */

    wchar_t *filesystem_encoding;
    wchar_t *filesystem_errors;

    wchar_t *pycache_prefix;  /* PYTHONPYCACHEPREFIX, -X pycache_prefix=PATH */
    int parse_argv;           /* Parse argv command line arguments? */
    PyWideStringList argv;
    wchar_t *program_name;

    PyWideStringList xoptions;     /* Command line -X options */
    PyWideStringList warnoptions;

    int site_import;
    int bytes_warning;
    int inspect;
    int interactive;
    int optimization_level;
    int parser_debug;
    int write_bytecode;
    int verbose;
    int quiet;
    int user_site_directory;
    int configure_c_stdio;
    int buffered_stdio;

    wchar_t *stdio_encoding;
    wchar_t *stdio_errors;

#ifdef MS_WINDOWS
    int legacy_windows_stdio;
#endif

    wchar_t *check_hash_pycs_mode;

    int pathconfig_warnings;

    wchar_t *pythonpath_env; /* PYTHONPATH environment variable */
    wchar_t *home;          /* PYTHONHOME environment variable,
                               see also Py_SetPythonHome(). */

    int module_search_paths_set;  /* If non-zero, use module_search_paths */
    PyWideStringList module_search_paths;  /* sys.path paths. Computed if
                                       module_search_paths_set is equal
                                       to zero. */

    wchar_t *executable;        /* sys.executable */
    wchar_t *base_executable;   /* sys._base_executable */
    wchar_t *prefix;            /* sys.prefix */
    wchar_t *base_prefix;       /* sys.base_prefix */
    wchar_t *exec_prefix;       /* sys.exec_prefix */
    wchar_t *base_exec_prefix;  /* sys.base_exec_prefix */

    int skip_source_first_line;

    wchar_t *run_command;   /* -c command line argument */
    wchar_t *run_module;    /* -m command line argument */
    wchar_t *run_filename;  /* Trailing command line argument without -c or -m */

    int _install_importlib;
    int _init_main;
} PyConfig;
#endif

typedef struct _err_stackitem {
    PyObject *exc_type, *exc_value, *exc_traceback;
    struct _err_stackitem *previous_item;
} _PyErr_StackItem;

#endif

typedef struct _ts {
#if PYMAJ > 2
    struct _ts *prev;
#endif

    struct _ts *next;
    PyInterpreterState *interp;

    struct _frame *frame;

    int recursion_depth;

#if PYMAJ > 2
    char overflowed;
    char recursion_critical;
#if PYMIN > 6
    int stackcheck_counter;
#endif
#endif

    int tracing;
    int use_tracing;

    void *c_profilefunc;
    void *c_tracefunc;

    PyObject *c_profileobj;
    PyObject *c_traceobj;

    PyObject *curexc_type;
    PyObject *curexc_value;
    PyObject *curexc_traceback;

#if PYMAJ > 3 && PYMIN > 6
    _PyErr_StackItem exc_state;
    _PyErr_StackItem *exc_info;
#else
    PyObject *exc_type;
    PyObject *exc_value;
    PyObject *exc_traceback;
#endif

    PyObject *dict;

#if PYMAJ < 3
    int tick_counter;
#endif
    int gilstate_counter;

    PyObject *async_exc;
    long thread_id;

    int trash_delete_nesting;
    PyObject *trash_delete_later;
    /* More things (?) */
} PyThreadState;

typedef struct _frame {
    PyObject_VAR_HEAD

    struct _frame *f_back;
    PyCodeObject *f_code;
    PyObject *f_builtins;
    PyObject *f_globals;
    PyObject *f_locals;
    PyObject **f_valuestack;

    PyObject **f_stacktop;
    PyObject *f_trace;

#if PYMAJ > 2
#if PYMIN > 6
    char f_trace_lines;
    char f_trace_opcodes;
#else
    PyObject *f_exc_type, *f_exc_value, *f_exc_traceback;
#endif
    PyObject *f_gen;
#else
    PyObject *f_exc_type, *f_exc_value, *f_exc_traceback;

    PyThreadState *f_tstate;
#endif

    int f_lasti;
    int f_lineno;
    int f_iblock;

    /* PRIVATE */
} PyFrameObject;

#if PYMAJ > 2

typedef int (*objobjproc)(PyObject *, PyObject *);
typedef int (*visitproc)(PyObject *, void *);
typedef int (*traverseproc)(PyObject *, visitproc, void *);
typedef int (*inquiry)(PyObject *);
typedef void (*freefunc)(void *);

#define PyObject_HEAD_INIT(type)        \
    { 1, type },

typedef struct PyModuleDef_Base {
    PyObject_HEAD
    PyObject* (*m_init)(void);
    Py_ssize_t m_index;
    PyObject* m_copy;
} PyModuleDef_Base;

#define PyModuleDef_HEAD_INIT { \
    PyObject_HEAD_INIT(NULL)    \
    NULL, /* m_init */          \
    0,    /* m_index */         \
    NULL, /* m_copy */          \
  }

typedef struct PyModuleDef{
    PyModuleDef_Base m_base;
    const char* m_name;
    const char* m_doc;
    Py_ssize_t m_size;
    PyMethodDef *m_methods;
    void* m_slots;
    traverseproc m_traverse;
    inquiry m_clear;
    freefunc m_free;
} PyModuleDef;

struct _frozen {
    char *name;
    unsigned char *code;
    int size;
};
#endif

#include "import-tab.h"
#include "Python-dynload-compat.h"

#endif // PYTHON_DYNLOAD_H
