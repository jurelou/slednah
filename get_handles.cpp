#include <cstring>
#include <memory>
#include <iostream>
#include <stdio.h>
#include <windows.h>
#include <ntdef.h>
#include <tchar.h>
#include <strsafe.h>
#include <psapi.h>

#define SystemHandleInformation 16
// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ne-ntifs-_object_information_class
#define ObjectTypeInformation 2
#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004
#define BUFSIZE 512

// source: https://processhacker.sourceforge.io/doc/struct___s_y_s_t_e_m___h_a_n_d_l_e___t_a_b_l_e___e_n_t_r_y___i_n_f_o.html
typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR ObjectTypeIndex;
    UCHAR HandleAttributes;
    USHORT HandleValue;
    PVOID Object;
    ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

// source: https://processhacker.sourceforge.io/doc/struct___s_y_s_t_e_m___h_a_n_d_l_e___i_n_f_o_r_m_a_t_i_o_n.html
typedef struct _SYSTEM_HANDLE_INFORMATION
{
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

/* source: https://github.com/winsiderss/systeminformer/blob/80affbbfad68726c3912c373ae8c4e01391bfd71/phnt/include/ntobapi.h#L84 */
// typedef struct _ObjectTypeInformation
// {
//     UNICODE_STRING TypeName;
//     ULONG TotalNumberOfObjects;
//     ULONG TotalNumberOfHandles;
//     ULONG TotalPagedPoolUsage;
//     ULONG TotalNonPagedPoolUsage;
//     ULONG TotalNamePoolUsage;
//     ULONG TotalHandleTableUsage;
//     ULONG HighWaterNumberOfObjects;
//     ULONG HighWaterNumberOfHandles;
//     ULONG HighWaterPagedPoolUsage;
//     ULONG HighWaterNonPagedPoolUsage;
//     ULONG HighWaterNamePoolUsage;
//     ULONG HighWaterHandleTableUsage;
//     ULONG InvalidAttributes;
//     GENERIC_MAPPING GenericMapping;
//     ULONG ValidAccessMask;
//     BOOLEAN SecurityRequired;
//     BOOLEAN MaintainHandleCount;
//     UCHAR TypeIndex; // since WINBLUE
//     CHAR ReservedByte;
//     ULONG PoolType;
//     ULONG DefaultPagedPoolCharge;
//     ULONG DefaultNonPagedPoolCharge;
// } OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;

// https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryobject
typedef struct __PUBLIC_OBJECT_TYPE_INFORMATION {
    UNICODE_STRING TypeName;
    ULONG Reserved [22];    // reserved for internal use
} PUBLIC_OBJECT_TYPE_INFORMATION, *PPUBLIC_OBJECT_TYPE_INFORMATION;


// https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation
typedef NTSTATUS(NTAPI *_NtQuerySystemInformation) (
	ULONG SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
);

// source: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-zwduplicateobject
typedef NTSTATUS(NTAPI *_NtDuplicateObject) (
	HANDLE SourceProcessHandle,
	HANDLE SourceHandle,
	HANDLE TargetProcessHandle,
	PHANDLE TargetHandle,
	ACCESS_MASK DesiredAccess,
	ULONG Attributes,
	ULONG Options
);

// source: https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryobject
typedef NTSTATUS(NTAPI *_NtQueryObject)(
	HANDLE ObjectHandle,
	ULONG ObjectInformationClass,
	PVOID ObjectInformation,
	ULONG ObjectInformationLength,
	PULONG ReturnLength
);

BOOL setDebugPrivilege()
{
    // TOKEN_PRIVILEGES tp;
    // LUID luid;

    // if ( !LookupPrivilegeValue( 
    //         NULL,            // lookup privilege on local system
    //         SE_DEBUG_NAME,   // privilege to lookup 
    //         &luid ) )        // receives LUID of privilege
    // {
    //     printf("LookupPrivilegeValue error: %u\n", GetLastError() ); 
    //     return FALSE; 
    // }
    // tp.PrivilegeCount = 1;
    // tp.Privileges[0].Luid = luid;
    // tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    // if ( !AdjustTokenPrivileges(
    //        hToken, 
    //        FALSE, 
    //        &tp, 
    //        sizeof(TOKEN_PRIVILEGES), 
    //        (PTOKEN_PRIVILEGES) NULL, 
    //        (PDWORD) NULL) )
    // { 
    //       printf("AdjustTokenPrivileges error: %u\n", GetLastError() ); 
    //       return FALSE; 
    // }
    return TRUE;
}

void psTree()
{
    // HANDLE procSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    // PROCESSENTRY32  *processInfo = new PROCESSENTRY32;

    // DWORD   my_pid = GetCurrentProcessId();
    // std::cout << "I AM PID: " << my_pid << std::endl;

    // processInfo->dwSize =sizeof(PROCESSENTRY32);
    // unsigned int index = 0;

    // while (Process32Next(procSnapshot, processInfo) != FALSE)
    // {
    //     ++index;
    //     // std::cout << processInfo->th32ParentProcessID << "->" << processInfo->th32ProcessID << " - " << processInfo->szExeFile << std::endl;
    //     if (processInfo->th32ProcessID == my_pid)
    //     {
    //         std::cout << "Skip self pid: " << processInfo->th32ProcessID << std::endl;
    //         continue;
    //     }
    //     HANDLE procHandle = OpenProcess(PROCESS_DUP_HANDLE, FALSE, processInfo->th32ProcessID);
    //     if (procHandle == NULL)
    //     {
    //         std::cout <<  "could not open process " << processInfo->szExeFile << " - " << processInfo->th32ProcessID << ": " << GetLastError() <<std::endl;
    //     }

    //     CloseHandle(procHandle);
    // }
    // CloseHandle(procSnapshot);

}


BOOL GetFileNameFromHandle(HANDLE handle, TCHAR *pszFilename)
{
    // source: https://learn.microsoft.com/en-us/windows/win32/memory/obtaining-a-file-name-from-a-file-handle
    HANDLE hFileMap;
    // TCHAR pszFilename[MAX_PATH + 1];
    // Get the file size.
    DWORD dwFileSizeHi = 0;
    DWORD dwFileSizeLo = GetFileSize(&handle, &dwFileSizeHi); 

    if( dwFileSizeLo == 0 && dwFileSizeHi == 0 )
    {
        std::cout << "Cannot map a file with a length of zero." << std::endl;
        return FALSE;
    }

  // Create a file mapping object.
    hFileMap = CreateFileMapping(handle, 
                    NULL,
                    PAGE_READONLY,
                    0, 
                    1,
                    NULL);
    if (!hFileMap)
        return FALSE;
        // Create a file mapping to get the file name.
    void* pMem = MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, 1);
    if (!pMem)
    {
        CloseHandle(hFileMap);
        return FALSE;
    }

    if (!GetMappedFileName(GetCurrentProcess(), 
        pMem, 
        pszFilename,
        MAX_PATH))
    {
        UnmapViewOfFile(pMem);
        CloseHandle(hFileMap);
        return FALSE;
    }
    // Translate path with device name to drive letters.
    TCHAR szTemp[BUFSIZE];
    szTemp[0] = '\0';

    if (GetLogicalDriveStrings(BUFSIZE-1, szTemp)) 
    {
        TCHAR szName[MAX_PATH];
        TCHAR szDrive[3] = TEXT(" :");
        BOOL bFound = FALSE;
        TCHAR* p = szTemp;

        do 
        {
            // Copy the drive letter to the template string
            *szDrive = *p;

            // Look up each device name
            if (QueryDosDevice(szDrive, szName, MAX_PATH))
            {
                size_t uNameLen = _tcslen(szName);

                if (uNameLen < MAX_PATH) 
                {
                    bFound = _tcsnicmp(pszFilename, szName, uNameLen) == 0
                        && *(pszFilename + uNameLen) == _T('\\');

                    if (bFound) 
                    {
                        // Reconstruct pszFilename using szTempFile
                        // Replace device path with DOS path
                        TCHAR szTempFile[MAX_PATH];
                        StringCchPrintf(szTempFile,
                                    MAX_PATH,
                                    TEXT("%s%s"),
                                    szDrive,
                                    pszFilename+uNameLen);
                        StringCchCopyN(pszFilename, MAX_PATH+1, szTempFile, _tcslen(szTempFile));
                    }
                }
            }
            // Go to the next NULL character.
            while (*p++);
        } while (!bFound && *p); // end of string
    }
    UnmapViewOfFile(pMem);
    CloseHandle(hFileMap);
    return TRUE;
}

int main(/*int ac, char **av*/)
{
    auto NtQuerySystemInformation = reinterpret_cast<_NtQuerySystemInformation >(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation"));
	auto NtDuplicateObject = reinterpret_cast<_NtDuplicateObject >(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtDuplicateObject"));
	auto NtQueryObject = reinterpret_cast<_NtQueryObject >(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryObject"));

    PSYSTEM_HANDLE_INFORMATION handleInfo;
    ULONG handleInfoSize = 0x10000;
    NTSTATUS status;
    ULONG i;
    HANDLE processHandle;

    if (NtQuerySystemInformation == NULL)
    {
        std::cout << "Could not load NtQuerySystemInformation !!!!" << std::endl;
    }
    handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(handleInfoSize);
    if (handleInfo == NULL)
    {
        std::cout << "Could not allocate memory for for handleInfo" << std::endl;
        return 1;
    }
	
    /* NtQuerySystemInformation ne donne pas la taille du buffer, donc on multiplie le buffer par 2 en boucle ...
    l'idée vient de: https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/get-all-open-handles-and-kernel-object-address-from-userland#code    
    TODO: c'est un peut naze. comment faire mieux????
    . */
	while ((status = NtQuerySystemInformation(SystemHandleInformation, handleInfo, handleInfoSize, NULL)) == STATUS_INFO_LENGTH_MISMATCH)
		handleInfo = (PSYSTEM_HANDLE_INFORMATION)realloc(handleInfo, handleInfoSize *= 2);

    if (!NT_SUCCESS(status))
    {
        std::cout << "NtQuerySystemInformation failed" << std::endl;
    }

    // Boucle sur les handles du système
    for (i = 0; i < handleInfo->NumberOfHandles; i++)
    {
        SYSTEM_HANDLE_TABLE_ENTRY_INFO handle = handleInfo->Handles[i];
        HANDLE processDupHandle = NULL;
        PPUBLIC_OBJECT_TYPE_INFORMATION objectTypeInfo;

        /* Ouvre un handle associé au PID du handle */
		if (!(processHandle = OpenProcess(PROCESS_DUP_HANDLE, FALSE, handle.UniqueProcessId)))
        {
            // std::cout << "Could not open process: " << handle.UniqueProcessId << std::endl;
            continue;
        }

        // Duplique le handle afin de pouvoir récupérer les infos
        if (!NT_SUCCESS(NtDuplicateObject(
                processHandle,
                (HANDLE)handle.HandleValue,
                GetCurrentProcess(),
                &processDupHandle,
                GENERIC_READ,
                0,
                0)))
        {
            // std::cout << "Failed to duplicate handle from PID: " << handle.UniqueProcessId << std::endl;
            CloseHandle(processHandle);
            CloseHandle(processDupHandle);
            continue;
        }

        // Récupération du type de handle
		objectTypeInfo = (PPUBLIC_OBJECT_TYPE_INFORMATION)malloc(0x1000);
        if (objectTypeInfo == NULL)
        {
			CloseHandle(processHandle);
			CloseHandle(processDupHandle);
			continue;
        }
		if (!NT_SUCCESS(NtQueryObject(processDupHandle, ObjectTypeInformation, objectTypeInfo, 0x1000, NULL)))
		{
			free(objectTypeInfo);
			CloseHandle(processHandle);
			CloseHandle(processDupHandle);
            std::cout << "Failed to ntquery " << GetLastError() << std::endl;
			continue;
		}

        // Pour chaque type d'objet, on récupère les valeurs
        if (wcscmp(objectTypeInfo->TypeName.Buffer, L"File") == 0 )
        {
        //    WCHAR* filename = new WCHAR[MAX_PATH]();
           TCHAR filename[MAX_PATH + 1];
            // std::wcout << "FILE: " << objectTypeInfo->TypeName.Buffer << std::endl;
            if (GetFileNameFromHandle(processDupHandle, filename))
            {
                std::cout << "FILE: " << handle.UniqueProcessId << " - "<< filename << std::endl;
            }
        }
        else
        {
        // std::wcout << handle.UniqueProcessId << " -> " << objectTypeInfo->TypeName.Buffer << std::endl;

        }

    }
    return 0;
}