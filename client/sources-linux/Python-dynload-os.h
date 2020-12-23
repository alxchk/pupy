#ifndef PYTHON_DYNLOAD_OS_H
#define PYTHON_DYNLOAD_OS_H

#define _GNU_SOURCE
#include <stdlib.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/mman.h>

#ifndef PYTHON_LIB_NAME
#error PYTHON_LIB_NAME must be specified
#endif

#include "Python-dynload.h"

#define FREE_HMODULE_AFTER_LOAD 1
#define FILE_SYSTEM_ENCODING "utf-8"
#define OS_PY_DL_EXT ".so"

typedef void *HMODULE;
typedef void *(*resolve_symbol_t)(HMODULE hModule, const char *name);

#ifndef OPENSSL_LIB_VERSION
#define OPENSSL_LIB_VERSION "1.0.0"
#endif

#define DEPENDENCIES                          \
{                                             \
    {                                         \
        "libcrypto.so." OPENSSL_LIB_VERSION,  \
        libcrypto_c_start,                    \
        libcrypto_c_size,                     \
        FALSE,                                \
        NULL                                  \
    }, {                                      \
        "libssl.so." OPENSSL_LIB_VERSION,     \
        libssl_c_start,                       \
        libssl_c_size,                        \
        FALSE,                                \
        NULL                                  \
    }, {                                      \
        PYTHON_LIB_NAME,                      \
        python_c_start,                       \
        python_c_size,                        \
        TRUE,                                 \
        NULL                                  \
    } , {                                     \
        NULL, NULL, NULL, NULL, NULL          \
    }                                         \
}

#define OSAlloc(size) malloc(size)
#define OSFree(ptr) free(ptr)

#define OSLoadLibrary(name) dlopen(name, RTLD_NOW)
#define OSResolveSymbol dlsym
#define OSUnmapRegion(region, size) munmap((void *) region, size)
#define MemLoadLibrary(name, bytes, size, arg) \
    memdlopen(name, bytes, size, RTLD_NOW | RTLD_GLOBAL)
#define MemResolveSymbol dlsym
#define CheckLibraryLoaded(name) dlopen(name, RTLD_NOW | RTLD_NOLOAD)

#ifndef PYTHON_DYNLOAD_OS_NO_BLOBS
static const char *OSGetProgramName()
{
    static BOOL is_set = FALSE;
    static char exe[PATH_MAX] = {'\0'};

    if (is_set)
        return exe;

#if defined(Linux)
    dprint("INVOCATION NAME: %s\n", program_invocation_name);

    if (readlink("/proc/self/exe", exe, sizeof(exe)) > 0)
    {
        if (strstr(exe, "/memfd:"))
        {
            snprintf(exe, sizeof(exe), "/proc/%d/exe", getpid());
        }
    }
    else
    {
        char *upx_env = getenv("   ");
        if (upx_env)
        {
            snprintf(exe, sizeof(exe), "%s", upx_env);
        }
    }

#elif defined(SunOS)
    strcpy(exe, getexecname());
#endif

    is_set = TRUE;
    return exe;
}

#include "python.c"
#include "libcrypto.c"
#include "libssl.c"
#include "tmplibrary.h"
#endif

#endif
