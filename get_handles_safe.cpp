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

void loadLibraries(
    std::shared_ptr<_NtQuerySystemInformation> &NtQuerySystemInformation)
{
    *NtQuerySystemInformation = reinterpret_cast<_NtQuerySystemInformation >(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation"));
	// *NtDuplicateObject = reinterpret_cast<_NtDuplicateObject >(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtDuplicateObject"));
	// *NtQueryObject = reinterpret_cast<_NtQueryObject >(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryObject"));

}

int main(/*int ac, char **av*/)
{
    PSYSTEM_HANDLE_INFORMATION handleInfo;
    ULONG handleInfoSize = sizeof(handleInfo);
    NTSTATUS status;

    _NtQuerySystemInformation NtQuerySystemInformation;
    _NtDuplicateObject NtDuplicateObject;
    _NtQueryObject NtQueryObject;

    if ((NtQuerySystemInformation = reinterpret_cast<_NtQuerySystemInformation >(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation"))) == NULL)
    {
        std::cout << "Could not load NtQuerySystemInformation" << std::endl;
        return 1;
    }
	if ((NtDuplicateObject = reinterpret_cast<_NtDuplicateObject >(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtDuplicateObject"))) == NULL)
    {
        std::cout << "Could not load NtDuplicateObject" << std::endl;
        return 1;
    }
	if ((NtQueryObject = reinterpret_cast<_NtQueryObject >(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryObject"))) == NULL)
    {
        std::cout << "Could not load NtQueryObject" << std::endl;
        return 1;
    }

    if ((handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(handleInfoSize)) == NULL)
    {
        std::cout << "Could not allocate memory for for handleInfo" << std::endl;
        return 1;
    }
    /* NtQuerySystemInformation ne donne pas la taille du buffer, donc on multiplie le buffer par 2 en boucle ...
    l'idée vient de: https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/get-all-open-handles-and-kernel-object-address-from-userland#code    
    . */
	while ((unsigned int)(status = NtQuerySystemInformation(SystemHandleInformation, handleInfo, handleInfoSize, NULL)) == STATUS_INFO_LENGTH_MISMATCH)
    {
		if ((handleInfo = (PSYSTEM_HANDLE_INFORMATION)realloc(handleInfo, handleInfoSize *= 2)) == NULL)
        {
            std::cout << "Could not re-allocate memory for for handleInfo" << std::endl;
            return 1;
        }
    }

    std::cout << "good" << std::endl;
    // if ((unsigned int)status == STATUS_INFO_LENGTH_MISMATCH)
    // {
    //     std::cout << "ooook" << status;
    // }
	// while ((status = NtQuerySystemInformation(SystemHandleInformation, handleInfo, handleInfoSize, NULL)) == STATUS_INFO_LENGTH_MISMATCH)
	// 	handleInfo = (PSYSTEM_HANDLE_INFORMATION)realloc(handleInfo, handleInfoSize *= 2);

    // handleInfo = new PSYSTEM_HANDLE_INFORMATION();


}