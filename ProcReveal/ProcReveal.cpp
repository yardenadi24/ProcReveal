
#include <Windows.h>
#include <Psapi.h>
#include <stdio.h>

#include "..\Reveal\RevealCommon.h"

bool ShowProcessModules(HANDLE hProcess)
{
    HMODULE hModules[1024];
    DWORD needed;

    // Get all modules for the process
    if (!EnumProcessModules(hProcess, hModules, sizeof(hModules), &needed))
    {
        printf("EnumProcessModules failed\n");
        return false;
    }

    // For each module get its name 
    for (int i = 0; i < (needed / sizeof(HMODULE)); i++)
    {
        WCHAR name[MAX_PATH];
        if (GetModuleBaseName(hProcess, hModules[i], name, _countof(name)))
        {
            printf("0x%p: %ws\n", hModules[i], name);
        }
    }
    return true;
}

int main(int argc, const char* argv[])
{
    if (argc < 2)
    {
        printf("Usage: ProcReveal <pid>\n");
        return 0;
    }

    // Get pid from args with ascii to int func
    DWORD pid = atoi(argv[1]);

    // Call openProcess
    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);

    if (!hProcess)
    {
        printf("Failed in OpenProcess.\nAttempting to access driver...\n");
        HANDLE hFile = CreateFile(L"\\\\.\\Reveal", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
        if (hFile != INVALID_HANDLE_VALUE)
        {
            DWORD bytes;
            OpenProcessData data;
            data.ProcessId = pid;
            data.Access = PROCESS_VM_READ | PROCESS_QUERY_INFORMATION;
            DeviceIoControl(hFile, IOCTL_OPEN_PROCESS, &data, sizeof(data), &hProcess, sizeof(hProcess), &bytes, NULL);
            CloseHandle(hFile);
            if (hProcess)
            {
                printf("Driver opened handle successfully.\n");
            }
            else {
                printf("Failed getting process using the driver.\n");
            }
        }
        else {
            printf("Could not open driver.\n");
        }
    }

    if (hProcess)
    {
        ShowProcessModules(hProcess);
        CloseHandle(hProcess);
    }
    else {
        printf("Failed to open process handle.\n");
    }

    return 0;
}

