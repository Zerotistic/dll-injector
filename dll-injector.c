#include <Windows.h>
#include <stdio.h>

int main() {
    // The DLL path we want to inject and the target process id.
    char* dllpath[150], processName;
    int p_id;
    printf("Insert DLL path:\n");
    scanf("%140s", &dllpath);
    printf("Insert process name:\n");
    scanf("%as", &processName);
    p_id = getpid(processName);
    printf("Process ID: %d\n", p_id);
    printf("#### Starting ####\n");


    // Open target process handle
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, p_id);
    if (hProcess == NULL) {
        printf("[!] Unable to find the target process id: %d\n" , p_id);
        return 1;
    }

    printf("[+] Open target process handle\n");

    // Getting targt memory address for the dll path
    LPVOID dllpathMemoryAddr = VirtualAllocEx(hProcess, NULL, strlen(dllpath), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (dllpathMemoryAddr == NULL) {
        printf("[!] Unable to get memory address of target process for the DLL path");
        return 1;
    }
    printf("[+] Allocate the memory address to store the DLL path\n");

    // Writing the dll path to the target memory address
    BOOL succeedWrite = WriteProcessMemory(hProcess, dllpathMemoryAddr, dllpath, strlen(dllpath), NULL);
    if (!succeedWrite) {
        printf("[!] Unable to write to the memory address of target process the DLL path\n");
        return 1;
    }
    printf("[+] Writed the dllpath to memory\n");

    // Getting LoadLibreryA address
    FARPROC loadLibAddr = GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "LoadLibraryA");
    if (loadLibAddr == NULL) {
        printf("[!] Unable to get the memory address of LoadLibraryA function\n");
        return 1;
    }
    printf("[+] Allocate the memory address to LoadLibraryA function\n");

    // Create remote thread on the remote process to load the dll
    HANDLE rThread = CreateRemoteThread(hProcess, NULL, strlen(dllpath), (LPTHREAD_START_ROUTINE)loadLibAddr, dllpathMemoryAddr, NULL, NULL);
    if (rThread == NULL) {
        printf("[!] Unable to create thread to execute the LoadLibraryA function\n the error: %u\n", GetLastError());
        return 1;
    }
    printf("#### DLL INJECTED ####\n");


    return 0;
}
