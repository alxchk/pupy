#ifndef PYTHONINTERPRETER
#define PYTHONINTERPRETER

#include <windows.h>

typedef VOID (*on_exit_session_t)(VOID);
void on_exit_session(void);

void initialize(BOOL isDll);
DWORD WINAPI execute(LPVOID lpArg);
void deinitialize();

void setup_jvm_class();

#endif
