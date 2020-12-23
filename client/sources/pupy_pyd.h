#ifndef _PUPY_PYD_H
#define _PUPY_PYD_H

#include "pupy_load.h"

#if PYMAJ > 2
typedef PyObject* (*pupy_init_t)(void);
#else
typedef void* (pupy_init_t) (void);
#endif

typedef struct _pupy_pyd_args {
    PVOID *pvMemoryLibraries;
    on_exit_session_t cbExit;
    BOOL blInitialized;
    pupy_init_t pInit;
} _pupy_pyd_args_t;

#endif

#include "Python-dynload-compat.h"
