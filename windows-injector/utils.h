#pragma once

BOOLEAN syncGetShouldQuitValue(BOOLEAN* shouldQuit, HANDLE mutex);

void syncSetShouldQuitValue(BOOLEAN* shouldQuit, HANDLE mutex, BOOLEAN newValue);

int threadSafeFprintf(FILE* stream, const char* format, ...);