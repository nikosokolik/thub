#include <stdio.h>
#include <windows.h>
#include <stdarg.h>

#include "utils.h"


const LPCWSTR CAN_PRINT_MUTEX_NAME = L"CAN_PRINT_MUTEX";

BOOLEAN syncGetShouldQuitValue(BOOLEAN* shouldQuit, HANDLE mutex) {
    BOOLEAN returnValue;
    DWORD dwWaitResult = WaitForSingleObject(mutex, INFINITE);
    returnValue = *shouldQuit;
    ReleaseMutex(mutex);
    return returnValue;
}

void syncSetShouldQuitValue(BOOLEAN* shouldQuit, HANDLE mutex, BOOLEAN newValue) {
    DWORD dwWaitResult = WaitForSingleObject(mutex, INFINITE);
    *shouldQuit = newValue;
    ReleaseMutex(mutex);
}

int threadSafeFprintf(FILE* stream, const char* format, ...) {
    int ret;
    va_list fprintfArgs;
    HANDLE canPrintMutex = CreateMutex(NULL, FALSE, CAN_PRINT_MUTEX_NAME);

    va_start(fprintfArgs, format);
    // Aquire mutex for safe print
    DWORD dwWaitResult = WaitForSingleObject(canPrintMutex, INFINITE);

    ret = vfprintf(stream, format, fprintfArgs);

    // Release mutex for safe print
    ReleaseMutex(canPrintMutex);

    // Cleanup
    CloseHandle(canPrintMutex);
    va_end(fprintfArgs);

    return ret;
}