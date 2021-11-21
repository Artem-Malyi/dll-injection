#include <Windows.h>

#include "logger.h"

#pragma warning(disable:4996)
#pragma warning(disable:4995)

BOOL __GetUniqueTempPath(PWSTR wsTempFilePath, size_t tempFilePathLen);

extern "C" void __cdecl __Log2File(LPSTR string2Log)
{
    HANDLE hMutex = OpenMutexW(SYNCHRONIZE, FALSE, LOG_MUTEX_NAME);
    if (!hMutex || GetLastError() == ERROR_FILE_NOT_FOUND)
        hMutex = CreateMutexW(NULL, FALSE, LOG_MUTEX_NAME);

    DWORD dw = WaitForSingleObject(hMutex, 5000);
    if (dw == WAIT_OBJECT_0) 
    {
        static WCHAR wsPath2File[MAX_PATH] = {0};
        if (!wsPath2File[0])
        {        
            __GetUniqueTempPath(wsPath2File, MAX_PATH);
            wcscat(wsPath2File, L"\\" LOGFILE_NAME);
        }

        HANDLE hFile = CreateFileW(wsPath2File, FILE_READ_ACCESS | FILE_WRITE_ACCESS, FILE_SHARE_READ, 0, OPEN_ALWAYS, 0, 0);
        if (INVALID_HANDLE_VALUE == hFile)
        {
            ReleaseMutex(hMutex);
            return;
        }

        SetFilePointer(hFile, 0, NULL, FILE_END);

        DWORD dwStringLength = (DWORD)(strlen(string2Log));
        DWORD dwDataSize = 0;

        WriteFile(hFile, string2Log, dwStringLength, &dwDataSize, NULL);

        CloseHandle(hFile);  

        ReleaseMutex(hMutex);
    } 

    if (hMutex) 
        CloseHandle(hMutex);
}

BOOL __GetUniqueTempPath(PWSTR wsTempFilePath, size_t tempFilePathLen)
{
    if (!wsTempFilePath || !tempFilePathLen || tempFilePathLen < MAX_PATH)
        return FALSE;

    typedef HRESULT (STDAPICALLTYPE *SHGetKnownFolderPath_t)(
        __in REFKNOWNFOLDERID rfid,
        __in DWORD /* KNOWN_FOLDER_FLAG */ dwFlags,
        __in_opt DWORD hToken,
        __deref_out PWSTR *ppszPath // free *ppszPath with CoTaskMemFree
        ); 

    SHGetKnownFolderPath_t pSHGetKnownFolderPath = (SHGetKnownFolderPath_t)GetProcAddress(LoadLibraryA("Shell32.dll"), "SHGetKnownFolderPath");
    if (!pSHGetKnownFolderPath)
    {
        // We're running on Windows < 6.0 (Windows XP), so use the ordinary %tmp% folder
        GetTempPathW(MAX_PATH, wsTempFilePath);
        wsTempFilePath[wcslen(wsTempFilePath)-1] = 0;
        //OutputDebugStringW(L"GetTempPathW()");
        //OutputDebugStringW(wsTempFilePath);
        return TRUE;
    }

    // We're running on Windows 6.0 and above, (Vista, Win7 etc)
    PWSTR wsKnownFolderPath = NULL;
    // FOLDERID_LocalAppDataLow - {A520A1A4-1780-4FF6-BD18-167343C5AF16}
    GUID FOLDERID_LocalAppDataLow = { 0xA520A1A4, 0x1780, 0x4FF6, 0xBD, 0x18, 0x16, 0x73, 0x43, 0xC5, 0xAF, 0x16 };
    HRESULT hr = pSHGetKnownFolderPath(FOLDERID_LocalAppDataLow, 0, 0, &wsKnownFolderPath);
    //OutputDebugStringW(L"SHGetKnownFolderPath()");
    //OutputDebugStringW(wsKnownFolderPath);
    if (FAILED(hr))
        return FALSE;

    WCHAR wsTempPath[MAX_PATH] = {0};
    wcsncpy(wsTempFilePath, wsKnownFolderPath, MAX_PATH);
    CoTaskMemFree(wsKnownFolderPath);

    return TRUE;
}