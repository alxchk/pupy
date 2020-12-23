
/* --- Code for inlining --- */

#ifndef UNCOMPRESSED
#include "LzmaDec.h"
#include "debug.h"

#ifdef _WIN32
#define ALLOC(x) VirtualAlloc(NULL, x, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
#define FREE(x, size) VirtualFree(x, 0, MEM_RELEASE)
#define INVALID_ALLOC NULL
#else
#include <malloc.h>
#include <sys/mman.h>
#define ALLOC(size) mmap(NULL, size + (4096 - size%4096), PROT_WRITE	\
                         | PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
#define FREE(x, size) munmap((void *) x, size + (4096 - size%4096))
#define INVALID_ALLOC MAP_FAILED
#endif

static void *_lzalloc(void *p, size_t size) { p = p; return malloc(size); }
static void _lzfree(void *p, void *address) { p = p; free(address); }
static ISzAlloc _lzallocator = { _lzalloc, _lzfree };
#define lzmafree(x, size) do { FREE(x, size);}  while (0)

#else
#define lzmafree(x, size) do {} while (0)
#endif


static unsigned int charToUInt(const char *data) {
    union {
      unsigned int l;
      unsigned char c[4];
    } x;

    x.c[3] = data[0];
    x.c[2] = data[1];
    x.c[1] = data[2];
    x.c[0] = data[3];

    return x.l;
}

static void *lzmaunpack(const char *data, size_t size, Py_ssize_t *puncompressed_size) {
    unsigned char *uncompressed = NULL;
    SizeT uncompressed_size = 0;

#ifndef UNCOMPRESSED
    const Byte *wheader = (Byte *) data + sizeof(unsigned int);
    const Byte *woheader = (Byte *) wheader + LZMA_PROPS_SIZE;

    ELzmaStatus status;

    size_t srcLen;
    int res;
#endif

    uncompressed_size = charToUInt(data);
    dprint("lzmaunpack(%s, %d) -> expected size = %d\n", data, size, uncompressed_size);

#ifndef UNCOMPRESSED
    uncompressed = ALLOC(uncompressed_size);
    if (uncompressed == INVALID_ALLOC) {
        return NULL;
    }

    srcLen = size - sizeof(unsigned int) - LZMA_PROPS_SIZE;

    res = LzmaDecode(
        uncompressed, &uncompressed_size, woheader, &srcLen, wheader,
        LZMA_PROPS_SIZE, LZMA_FINISH_ANY, &status, &_lzallocator
    );

    if (res != SZ_OK) {
        FREE(uncompressed, uncompressed_size);
        return NULL;
    }
#else
    uncompressed = data + sizeof(unsigned int);
#endif

    if (puncompressed_size) {
        *puncompressed_size = uncompressed_size;
    }

    return uncompressed;
}

static PyObject *PyObject_lzmaunpack(const char *data, size_t size) {
    PyObject * object;
    Py_ssize_t uncompressed_size = 0;

    void *uncompressed = lzmaunpack(data, size, &uncompressed_size);
    if (!uncompressed) {
        PyErr_SetString(PyExc_Exception, "LZMA error");
        return NULL;
    }

    dprint("PyMarshal_ReadObjectFromString(%p, %d [sizeof=%d])\n",
        uncompressed, (int) uncompressed_size, sizeof(uncompressed_size));

    object = PyMarshal_ReadObjectFromString(
        uncompressed, uncompressed_size);

    lzmafree(uncompressed, uncompressed_size);
    return object;
}

#if PYMAJ < 3
static PyObject *PyDict_lzmaunpack(const char *data, size_t size) {
    PyObject * object = NULL;

    unsigned int keys;
    unsigned int ksize, vsize, i;

    size_t offset;

    PyObject *k = NULL;
    PyObject *v = NULL;

    Py_ssize_t uncompressed_size = 0;
    void *uncompressed = lzmaunpack(data, size, &uncompressed_size);
    if (!uncompressed) {
        return NULL;
    }

    object = PyDict_New();
    if (!object) {
        goto lbExit;
    }

    keys = charToUInt(uncompressed);

    for (i=0, offset=4; i<keys; i++) {
        ksize = charToUInt((char *) uncompressed + offset + 0);
        vsize = charToUInt((char *) uncompressed + offset + 4);

        offset += 8;

        k = PyString_FromStringAndSize((char *) uncompressed + offset, ksize);
        offset += ksize;

        v = PyBytes_FromStringAndSize((char *) uncompressed + offset, vsize);
        offset += vsize;

        if (!k || !v) {
            Py_XDECREF(k);
            Py_XDECREF(v);
            Py_XDECREF(object);
            object = NULL;
            goto lbExit;
        }

        PyDict_SetItem(object, k, v);
        Py_DECREF(k);
        Py_DECREF(v);
    }

 lbExit:
    lzmafree(uncompressed, uncompressed_size);
    return object;
}

#else

static BOOL is_py_ext(const char *path, size_t path_size)
{
    if (path_size < 3 || path_size > 4)
        return FALSE;

    return path[0] == '.' && path[1] == 'p' && path[2] == 'y';
}

static BOOL is_same_module(const char *module_name, const char *path, size_t path_size) {
    const char *m = module_name;
    const char *p = path;

    if (!module_name || !path || !*module_name || !*path)
        return FALSE;

    while (*m && path_size) {
        if ((*p != *m) && ((*m != '.') || (*p != '/'))) {
            if (*m == '*')
                return path_size != 0;
            else
                return FALSE;
        }

        ++ m, ++ p, -- path_size;
    }

    return (path_size == 0 && *m == '\0') || (*m == '\0' && is_py_ext(p, path_size));
}

static char *as_module_name(const char* module_path, size_t length, BOOL *is_package) {
    size_t required = 0;
    size_t last_required = 0;

    const char *c;
    char *r;
    char *last = NULL;
    char *result = NULL;
    size_t i;

    for (c = module_path, i=0; i<length; ++ c, ++i) {
        ++ required;

        if (*c == '.') {
            last_required = required;
        }
    }

    if (!last_required)
        return NULL;

    result = OSAlloc(last_required);
    if (!result)
        return NULL;

    for (c = module_path, r = result, i=0; i < last_required - 1; ++ c, ++ r, ++ i)
        if (*c == '/') {
            *r = '.';
            last = r;
        } else
            *r = *c;

    *r = '\0';

    if (last && !strcmp(last, ".__init__")) {
        if (is_package)
            *is_package = TRUE;

        *last = '\0';
    } else {
        if (is_package)
            *is_package = FALSE;
    }

    return result;
}


static BOOL is_module_in_list(
    const char *path, size_t path_size, const char *list[])
{
    for (const char **item = list; *item; ++ item)
        if (is_same_module(*item, path, path_size))
            return TRUE;

    return FALSE;
}


struct _frozen * PyFrozen_fromKV(
    const char *uncompressed, Py_ssize_t uncompressed_size, const char* preload[])
{
    unsigned int keys;
    unsigned int ksize, vsize, i, f;

    size_t offset;
    size_t frozen_required;

    const struct _frozen *iter = PyImport_FrozenModules;
    const struct _frozen *_frozen_importlib = NULL;
    const struct _frozen *_frozen_importlib_external = NULL;
    struct _frozen *_frozen_replace = NULL;

    while (iter && iter->name) {
        if (!strcmp(iter->name, "_frozen_importlib")) {
            _frozen_importlib = iter;
        } else if (!strcmp(iter->name, "_frozen_importlib_external")) {
            _frozen_importlib_external = iter;
        }

        ++ iter;
    }

    if (!_frozen_importlib || !_frozen_importlib_external)
        return NULL;

    keys = charToUInt(uncompressed);

    frozen_required = 3; // _frozen_importlib + + _frozen_importlib_external + null

    for (i=0, offset=4; i<keys; i++) {
        ksize = charToUInt((char *) uncompressed + offset + 0);
        vsize = charToUInt((char *) uncompressed + offset + 4);

        offset += 8;

        if (is_module_in_list((char *)uncompressed + offset, ksize, preload))
            ++ frozen_required;

        offset += ksize + vsize;
    }

    _frozen_replace = OSAlloc(sizeof(struct _frozen) * frozen_required);
    if (!_frozen_replace)
        return NULL;

    _frozen_replace[0].name = _frozen_importlib->name;
    _frozen_replace[0].code = _frozen_importlib->code;
    _frozen_replace[0].size = _frozen_importlib->size;

    _frozen_replace[1].name = _frozen_importlib_external->name;
    _frozen_replace[1].code = _frozen_importlib_external->code;
    _frozen_replace[1].size = _frozen_importlib_external->size;

    f = 2;

    for (i=0, offset=4; i<keys && f < frozen_required - 1; i++) {
        BOOL is_package = FALSE;

        ksize = charToUInt((char *) uncompressed + offset + 0);
        vsize = charToUInt((char *) uncompressed + offset + 4);

        offset += 8;

        if (!is_module_in_list((char *)uncompressed + offset, ksize, preload)) {
            offset += ksize + vsize;
            continue;
        }

        _frozen_replace[f].name = as_module_name(
            (char *)uncompressed + offset, ksize, &is_package
        );

        offset += ksize;

        _frozen_replace[f].code = OSAlloc(vsize);
        if (_frozen_replace[f].code) {
            memcpy(
                _frozen_replace[f].code,
                (char *)uncompressed + offset + (4 * 4),
                vsize - (4 * 4)
            );

            _frozen_replace[f].size = is_package? -vsize : vsize;
        }

        offset += vsize;

        dprint(
            "Set frozen library: %s (%d)\n",
            _frozen_replace[f].name,
            _frozen_replace[f].size
        );

        ++ f;
    }

    _frozen_replace[frozen_required - 1].name = NULL;
    _frozen_replace[frozen_required - 1].code = NULL;
    _frozen_replace[frozen_required - 1].size = 0;

    return _frozen_replace;
}


static PyObject *PyLibrary_fromKV(
    const char *uncompressed, Py_ssize_t uncompressed_size, const char* exceptions[]) {

    PyObject * object = NULL;

    unsigned int keys;
    unsigned int ksize, vsize, i;

    size_t offset;

    PyObject *k = NULL;
    PyObject *v = NULL;

    object = PyDict_New();
    if (!object) {
        goto lbExit;
    }

    keys = charToUInt(uncompressed);

    for (i=0, offset=4; i<keys; i++) {
        ksize = charToUInt((char *) uncompressed + offset + 0);
        vsize = charToUInt((char *) uncompressed + offset + 4);

        offset += 8;

        if (is_module_in_list((char *) uncompressed + offset, ksize, exceptions)) {
            offset += ksize + vsize;
            continue;
        }

        k = PyString_FromStringAndSize((char *) uncompressed + offset, ksize);
        offset += ksize;

        v = PyBytes_FromStringAndSize((char *) uncompressed + offset, vsize);
        offset += vsize;

        if (!k || !v) {
            Py_XDECREF(k);
            Py_XDECREF(v);
            Py_XDECREF(object);
            object = NULL;
            goto lbExit;
        }

        PyDict_SetItem(object, k, v);
        Py_DECREF(k);
        Py_DECREF(v);
    }

 lbExit:
    return object;
}

#endif
