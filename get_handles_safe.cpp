#include <cstring>
#include <memory>
#include <iostream>
#include <stdio.h>

#include <windows.h>
#include <psapi.h>

#include <ntdef.h>
// #include <tchar.h>

#define SystemHandleInformation 16
// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FType%20independed%2FOBJECT_NAME_INFORMATION.html
#define ObjectNameInformation 1
#define ObjectTypeInformation 2

#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004
#define BUFF_SIZE 1000

// https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryobject
typedef struct __PUBLIC_OBJECT_TYPE_INFORMATION {
    UNICODE_STRING TypeName;
    ULONG Reserved [22];    // reserved for internal use
} PUBLIC_OBJECT_TYPE_INFORMATION, *PPUBLIC_OBJECT_TYPE_INFORMATION;

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


BOOL getObjectName(const _NtQueryObject &NtQueryObject, const HANDLE &processDupHandle, UNICODE_STRING &objectName)
{
    PVOID   objectNameInfo;
    ULONG   returnLength;

    if ((objectNameInfo = malloc(0x1000)) == NULL)
    {
        return FALSE;
    }

	if (!NT_SUCCESS(NtQueryObject(processDupHandle, ObjectNameInformation, objectNameInfo, 0x1000, &returnLength)))
    {
        // NtQuery failed, surement à cause du manque de buffer, donc on réaloue
        if ((objectNameInfo = realloc(objectNameInfo, returnLength)) == NULL)
        {
            free(objectNameInfo);
            return FALSE;
        }
        // On réessaye de récupérer le nom de l'objet
        if (!NT_SUCCESS(NtQueryObject(processDupHandle, ObjectNameInformation, objectNameInfo, returnLength, NULL)))
        {
            free(objectNameInfo);
            return FALSE;
        }
    }

    objectName = *(PUNICODE_STRING)objectNameInfo;
    free(objectNameInfo);
    return objectName.Length > 0;
}

BOOL getObjectType(const _NtQueryObject &NtQueryObject, const HANDLE &processDupHandle, PUBLIC_OBJECT_TYPE_INFORMATION *objectTypeInfo)
{
	return NT_SUCCESS(NtQueryObject(processDupHandle, ObjectTypeInformation, objectTypeInfo, 0x1000, NULL));
}

BOOL getHandleInfo(
    const SYSTEM_HANDLE_TABLE_ENTRY_INFO  &handle,
    const _NtDuplicateObject &NtDuplicateObject,
    const _NtQueryObject &NtQueryObject)
{
    UNICODE_STRING objectName;
    HANDLE  processHandle = NULL;
    HANDLE  processDupHandle = NULL;
    PUBLIC_OBJECT_TYPE_INFORMATION *objectTypeInfo = new PUBLIC_OBJECT_TYPE_INFORMATION;

    /* Ouvre un handle sur le processus associé au handle */
	if (!(processHandle = OpenProcess(PROCESS_DUP_HANDLE, FALSE, handle.UniqueProcessId)))
    {
        // std::cout << "Could not open handle on process: " << handle.UniqueProcessId << std::endl;
		delete objectTypeInfo;
        return FALSE;
    }

    // Duplique le handle afin de pouvoir récupérer les infos
    if (!NT_SUCCESS(NtDuplicateObject(
        processHandle,
        (HANDLE)(intptr_t)handle.HandleValue,
        GetCurrentProcess(),
        &processDupHandle,
        GENERIC_READ,
        0,
        0)
    ))
    {
		delete objectTypeInfo;
        CloseHandle(processDupHandle);
        CloseHandle(processHandle);
        return FALSE;
    }
    // Récupération du type d'objet
    if (!getObjectType(NtQueryObject, processDupHandle, objectTypeInfo))
    {
		delete objectTypeInfo;
		CloseHandle(processDupHandle);
		CloseHandle(processHandle);
		return FALSE;
    }
    // std::wcout <<"-> " << objectTypeInfo->TypeName.Buffer << std::endl;
    if (wcscmp(objectTypeInfo->TypeName.Buffer, L"File") == 0 )
    {

    }
    else if (getObjectName(NtQueryObject, processDupHandle, objectName))
    {
        std::wcout << "ELSE: " << objectName.Buffer << std::endl;
    }
    delete objectTypeInfo;
	CloseHandle(processDupHandle);
	CloseHandle(processHandle);
    return TRUE;
}

BOOL getSystemHandles(const _NtQuerySystemInformation &NtQuerySystemInformation, PSYSTEM_HANDLE_INFORMATION &handleInfo)
{
    NTSTATUS status;
    ULONG handleInfoSize = 0x1000;

    /* NtQuerySystemInformation ne donne pas la taille du buffer, donc on multiplie le buffer par 2 en boucle ...
    l'idée vient de: https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/get-all-open-handles-and-kernel-object-address-from-userland#code
    . */
    if ((handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(handleInfoSize)) == NULL)
    {
        std::cout << "Could not allocate memory for handleInfo" << std::endl;
        return FALSE;
    }

	while ((ULONG)(status = NtQuerySystemInformation(SystemHandleInformation, handleInfo, handleInfoSize, NULL)) == STATUS_INFO_LENGTH_MISMATCH)
    {
		if ((handleInfo = (PSYSTEM_HANDLE_INFORMATION)realloc(handleInfo, handleInfoSize *= 2)) == NULL)
        {
            std::cout << "Could not re-allocate memory for for handleInfo" << std::endl;
            return FALSE;
        }
    }
    if (!NT_SUCCESS(status))
    {
        std::cout << "Could not get system informations" << std::endl;
        return FALSE;
    }
    return TRUE;
}

int main(/*int ac, char **av*/)
{
    PSYSTEM_HANDLE_INFORMATION handleInfo;
    HMODULE ntdllModule;
    ULONG   i;
    DWORD   my_pid = GetCurrentProcessId();

    _NtQuerySystemInformation NtQuerySystemInformation;
    _NtDuplicateObject NtDuplicateObject;
    _NtQueryObject NtQueryObject;

    /* chargement du module ntdll */
    if ((ntdllModule = GetModuleHandleA("ntdll.dll")) == NULL)
    {
        std::cout << "Could not load ntdll.dll" << std::endl;
        return 1;
    }
    /* récupération des fonctions exportées de ntdll */
    if ((NtQuerySystemInformation = reinterpret_cast<_NtQuerySystemInformation >(GetProcAddress(ntdllModule, "NtQuerySystemInformation"))) == NULL)
    {
        std::cout << "Could not load NtQuerySystemInformation" << std::endl;
        return 1;
    }
	if ((NtDuplicateObject = reinterpret_cast<_NtDuplicateObject >(GetProcAddress(ntdllModule, "NtDuplicateObject"))) == NULL)
    {
        std::cout << "Could not load NtDuplicateObject" << std::endl;
        return 1;
    }
	if ((NtQueryObject = reinterpret_cast<_NtQueryObject >(GetProcAddress(ntdllModule, "NtQueryObject"))) == NULL)
    {
        std::cout << "Could not load NtQueryObject" << std::endl;
        return 1;
    }

    if (!getSystemHandles(NtQuerySystemInformation, handleInfo))
        return 1;

    for (i = 0; i < handleInfo->NumberOfHandles; i++)
    {
        if (handleInfo->Handles[i].UniqueProcessId != my_pid)
        {
            getHandleInfo(handleInfo->Handles[i], NtDuplicateObject, NtQueryObject);
            // std::cout << handleInfo->Handles[i].UniqueProcessId << std::endl;
        }
    }

    // std::cout << "good" << std::endl;



}