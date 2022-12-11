#include <cstring>
#include <memory>
#include <sstream>
#include <iostream>
#include <stdio.h>
#include <vector>

#include <windows.h>
#include <psapi.h>

#include <ntdef.h>
#include <tchar.h>

#define SystemExtendedHandleInformation 0x40

constexpr auto ObjInherit = 2L;

constexpr auto ObjPermanent = 16L;
constexpr auto ObjExclusive = 32L;
constexpr auto ObjCaseIncensitive = 64L;
constexpr auto ObjOpenif = 128L;
constexpr auto ObjOpenlink = 256L;
constexpr auto ObjKernelHandle = 512L;
constexpr auto ObjForceAccessCheck = 1024L;
constexpr auto ObjIgnoreImpersonatedDevicemap = 2048L;
constexpr auto ObjDontReparse = 4096L;
constexpr auto ObjValidAttributed = 8178L;

#define STATUS_SUCCESS 0L

constexpr BOOL isConsoleHandle(const HANDLE &handle) {
 return ((((ULONG_PTR)handle) & 0x10000003) == 0x3);
}

constexpr auto STATUS_INFO_LENGTH_MISMATCH = 0xc0000004;

using ObjectInfoTuple = std::tuple<std::string, std::string>;


typedef enum _SYSTEM_INFORMATION_CLASS {
  SystemBasicInformation,
  SystemProcessorInformation,
  SystemPerformanceInformation,
  SystemTimeOfDayInformation,
  SystemPathInformation,
  SystemProcessInformation,
  SystemCallCountInformation,
  SystemDeviceInformation,
  SystemProcessorPerformanceInformation,
  SystemFlagsInformation,
  SystemCallTimeInformation,
  SystemModuleInformation,
  SystemLocksInformation,
  SystemStackTraceInformation,
  SystemPagedPoolInformation,
  SystemNonPagedPoolInformation,
  SystemHandleInformation
} SYSTEM_INFORMATION_CLASS;

typedef enum _OBJECT_INFORMATION_CLASS {
  ObjectBasicInformation,
  ObjectNameInformation,
  ObjectTypeInformation,
  ObjectAllTypesInformation,
  ObjectHandleInformation
} OBJECT_INFORMATION_CLASS;

typedef struct _OBJECT_NAME_INFORMATION {
  UNICODE_STRING Name;
} OBJECT_NAME_INFORMATION, *POBJECT_NAME_INFORMATION;

typedef NTSTATUS(WINAPI* ZwQueryObject)(HANDLE h,
                                        OBJECT_INFORMATION_CLASS oic,
                                        PVOID ObjectInformation,
                                        ULONG ObjectInformationLength,
                                        PULONG ReturnLength);

typedef NTSTATUS(NTAPI* NtQuerySystemInformation)(ULONG SystemInformationClass,
	                                              PVOID SystemInformation,
	                                              ULONG SystemInformationLength,
	                                              PULONG ReturnLength);
                                                
typedef NTSTATUS(NTAPI* ZwDuplicateObject)(HANDLE SourceProcessHandle,
	                                         HANDLE SourceHandle,
	                                         HANDLE TargetProcessHandle,
	                                         PHANDLE TargetHandle,
	                                         ACCESS_MASK DesiredAccess,
	                                         ULONG HandleAttributes,
	                                         ULONG Options);

typedef NTSTATUS(NTAPI* NtDuplicateObject)(HANDLE SourceProcessHandle,
	                                         HANDLE SourceHandle,
	                                         HANDLE TargetProcessHandle,
	                                         PHANDLE TargetHandle,
	                                         ACCESS_MASK DesiredAccess,
	                                         ULONG Attributes,
	                                         ULONG Options);

typedef NTSTATUS(NTAPI* NtQueryObject)(HANDLE ObjectHandle,
                                       ULONG ObjectInformationClass,
                                       PVOID ObjectInformation,
                                       ULONG ObjectInformationLength,
                                       PULONG ReturnLength);

typedef struct __PUBLIC_OBJECT_TYPE_INFORMATION {
    UNICODE_STRING TypeName;
    ULONG Reserved [22];    // reserved for internal use
} PUBLIC_OBJECT_TYPE_INFORMATION, *PPUBLIC_OBJECT_TYPE_INFORMATION;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
{
    PVOID Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;


typedef struct _SYSTEM_HANDLE_INFORMATION_EX
{
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;


struct utf_converter {
  std::wstring from_bytes(const std::string& str) {
    std::wstring result;
    if (str.length() > 0) {
      result.resize(str.length() * 2);
      auto count = MultiByteToWideChar(
          CP_UTF8, 0, str.c_str(), -1, &result[0], str.length() * 2);
      result.resize(count - 1);
    }

    return result;
  }

  std::string to_bytes(const std::wstring& str) {
    std::string result;
    if (str.length() > 0) {
      result.resize(str.length() * 4);
      auto count = WideCharToMultiByte(CP_UTF8,
                                       0,
                                       str.c_str(),
                                       -1,
                                       &result[0],
                                       str.length() * 4,
                                       NULL,
                                       NULL);
      result.resize(count - 1);
    }

    return result;
  }
};

static utf_converter converter;

std::string wstringToString(const std::wstring& src) {
  std::string utf8_str = converter.to_bytes(src);
  return utf8_str;
}

std::string wstringToString(const wchar_t* src) {
  if (src == nullptr) {
    return std::string("");
  }

  std::string utf8_str = converter.to_bytes(src);
  return utf8_str;
}


BOOL getObjectName(const NtQueryObject &_NtQueryObject,
                     const HANDLE &processDupHandle, std::string &objectName) {
  NTSTATUS ntStatus;
  std::unique_ptr<char[]> objectNameInfoBuf;
  ULONG objectNameInfoBufLen = sizeof(OBJECT_NAME_INFORMATION);

  if (processDupHandle == 0 || processDupHandle == INVALID_HANDLE_VALUE) {
    return FALSE;
  }

  // NtQueryObject returns STATUS_INVALID_HANDLE for Console handles
  if (isConsoleHandle(processDupHandle)) {
    std::stringstream sstream;
    sstream << "\\Device\\Console";
    sstream << std::hex << (DWORD)(DWORD_PTR)processDupHandle;
    objectName = sstream.str();
    return TRUE;
  }

  while (true) {
    objectNameInfoBuf = std::make_unique<char[]>(objectNameInfoBufLen);
    ntStatus = _NtQueryObject(processDupHandle, ObjectNameInformation, objectNameInfoBuf.get(),
                     objectNameInfoBufLen, &objectNameInfoBufLen);
    if (ntStatus == STATUS_INFO_LENGTH_MISMATCH) {
        continue;
    }
    if (!NT_SUCCESS(ntStatus)) {
        return FALSE;
    }
    break;
  }

  auto objectNameInfo = reinterpret_cast<POBJECT_NAME_INFORMATION>(objectNameInfoBuf.get());
  if (!objectNameInfo->Name.Length || !objectNameInfo->Name.Buffer) {
    return FALSE;
  }
  objectName = wstringToString(objectNameInfo->Name.Buffer);
  return TRUE;
}

// Code adapted from:
// https://learn.microsoft.com/en-us/windows/win32/memory/obtaining-a-file-name-from-a-file-handle
BOOL getFilenameObject(HANDLE handle, std::string &filename) {
  LPVOID pMem;
  HANDLE hFileMap;
  LPSTR pszFilename = new char[MAX_PATH + 1];
  LPSTR tempDriveName = new char[MAX_PATH + 1];
  LPSTR szTemp = new char[MAX_PATH];
  TCHAR szDrive[3] = TEXT("A:");
  // DWORD dwFileSizeHi = 0;
  // DWORD dwFileSizeLo = GetFileSize(&handle, &dwFileSizeHi);

  // if (dwFileSizeLo == 0 && dwFileSizeHi == 0) {
  //   return FALSE;
  // }

  // GUARD pszFilename : delete pszFilename ou LocalFree(pszFilename);
  // GUARD tempDriveName : delete tempDriveName
  // GUARD szTemp : delete szTemp

  // Create a file mapping object.
  hFileMap = CreateFileMapping(handle, NULL, PAGE_READONLY, 0, 1, NULL);
  if (!hFileMap) {
    return FALSE;
  }
  //GUARD: CloseHandle(hFileMap);

  // Create a file mapping to get the file name.
  if (!(pMem = MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, 1))) {
    return FALSE;
  }

  // GUARD: UnmapViewOfFile(pMem);

  if (!GetMappedFileName(GetCurrentProcess(), pMem, pszFilename, MAX_PATH)) {
    return FALSE;
  }

  // Translate path with device name to drive letters.
  if (GetLogicalDriveStrings(MAX_PATH - 1, szTemp)) {

    // Guess drive letter by iterating of letters A-Z
    while (szDrive[0] != 'Z') {
      if (QueryDosDevice(szDrive, tempDriveName, MAX_PATH)) {
        size_t uNameLen = _tcslen(tempDriveName);
        filename = szDrive;
        filename.append(pszFilename + uNameLen);
        break;
      }
      szDrive[0]++;
    }
  } else {
    filename = pszFilename;
  }
  return TRUE;
}


std::string getHandleAttributes(const ULONG &handleAttributes) {

  std::stringstream ss;

  if ((handleAttributes & ObjInherit) == ObjInherit) {
    ss << "OBJ_INHERIT";
  }
  if ((handleAttributes & ObjPermanent) == ObjPermanent) {
    ss << ",OBJ_PERMANENT";
  }
  if ((handleAttributes & ObjExclusive) == ObjExclusive) {
    ss << ",OBJ_EXCLUSIVE";
  }
  if ((handleAttributes & ObjCaseIncensitive) == ObjCaseIncensitive) {
    ss << ",OBJ_CASE_INSENSITIVE";
  }
  if ((handleAttributes & ObjOpenif) == ObjOpenif) {
    ss << ",OBJ_OPENIF";
  }
  if ((handleAttributes & ObjOpenlink) == ObjOpenlink) {
    ss << ",OBJ_OPENLINK";
  }
  if ((handleAttributes & ObjKernelHandle) == ObjKernelHandle) {
    ss << ",OBJ_KERNEL_HANDLE";
  }
  if ((handleAttributes & ObjForceAccessCheck) == ObjForceAccessCheck) {
    ss << ",OBJ_FORCE_ACCESS_CHECK";
  }
  if ((handleAttributes & ObjIgnoreImpersonatedDevicemap) ==
      ObjIgnoreImpersonatedDevicemap) {
    ss << ",OBJ_IGNORE_IMPERSONATED_DEVICEMAP";
  }
  if ((handleAttributes & ObjDontReparse) == ObjDontReparse) {
    ss << ",OBJ_DONT_REPARSE";
  }
  if ((handleAttributes & ObjValidAttributed) == ObjValidAttributed) {
    ss << ",OBJ_VALID_ATTRIBUTES";
  }

  std::string handlesAttrsString = ss.str();
  if (!handlesAttrsString.empty() && handlesAttrsString.front() == ',') {
    handlesAttrsString.erase(handlesAttrsString.begin());
  }
  return handlesAttrsString;
}

BOOL getHandleInfo(const HANDLE &handle, const NtQueryObject &_NtQueryObject,
                     ObjectInfoTuple &objInfo) {
  std::string objectName;

  std::unique_ptr<char[]> objectTypeInfoBuf;
  NTSTATUS ntStatus;
  ULONG objectTypeInfoBufLen = sizeof(PUBLIC_OBJECT_TYPE_INFORMATION);

  while (true) {
    objectTypeInfoBuf = std::make_unique<char[]>(objectTypeInfoBufLen);
    ntStatus = _NtQueryObject(handle, ObjectTypeInformation, objectTypeInfoBuf.get(),
                     objectTypeInfoBufLen, &objectTypeInfoBufLen);
    if (ntStatus == STATUS_INFO_LENGTH_MISMATCH) {
        continue;
    }
    if (!NT_SUCCESS(ntStatus)) {
        return FALSE;
    }
    break;
  }

  auto objectTypeInfo = reinterpret_cast<PPUBLIC_OBJECT_TYPE_INFORMATION>(objectTypeInfoBuf.get());

  std::get<0>(objInfo) = wstringToString(objectTypeInfo->TypeName.Buffer);

  // If it's a file, try to retrieve the human readable path name
  // Otherwise, dumps the full object name
  if (wcscmp(objectTypeInfo->TypeName.Buffer, L"File") == 0) {
    std::string filename;
    auto status = getFilenameObject(handle, filename);
    if (status) {
      std::get<1>(objInfo) = filename;
      return TRUE;
    }
  } else if (getObjectName(_NtQueryObject, handle, objectName)) {
    std::get<1>(objInfo) = objectName;
    return TRUE;
  }

  return FALSE;
}


BOOL getSystemHandles(const NtQuerySystemInformation &_NtQuerySystemInformation, std::unique_ptr<char[]> &handleInfoBuf) {
  NTSTATUS ntStatus;
  ULONG handleInfoBufLen = sizeof(SYSTEM_HANDLE_INFORMATION_EX) +
                           1024 * sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX);

  while (true) {
    handleInfoBuf = std::make_unique<char[]>(handleInfoBufLen);
    ntStatus = _NtQuerySystemInformation(
                     SystemExtendedHandleInformation, handleInfoBuf.get(),
                     handleInfoBufLen, &handleInfoBufLen);
    if (ntStatus == STATUS_INFO_LENGTH_MISMATCH) {
        continue;
    }
    if (!NT_SUCCESS(ntStatus)) {
        return FALSE;
    }
    break;
  }
  return TRUE;
}


int main(/*int ac, char **av*/) {
  ULONG i;
  HANDLE processHandle;
  HANDLE processDupHandle;

  std::unique_ptr<char[]> handleInfoBuf;
//   std::vector<PSYSTEM_HANDLE_INFORMATION_EX> handleInfo;
//   PSYSTEM_HANDLE_INFORMATION_EX handleInfo;
  SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX handle;
  HMODULE ntdllModule = NULL;

  GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, "ntdll.dll",
                     &ntdllModule);
  auto _NtDuplicateObject = reinterpret_cast<NtDuplicateObject>(
      GetProcAddress(ntdllModule, "NtDuplicateObject"));
  auto _NtQueryObject = reinterpret_cast<NtQueryObject>(
      GetProcAddress(ntdllModule, "NtQueryObject"));
  auto _NtQuerySystemInformation = reinterpret_cast<NtQuerySystemInformation>(
      GetProcAddress(ntdllModule, "NtQuerySystemInformation"));

  auto status = getSystemHandles(_NtQuerySystemInformation, handleInfoBuf);

  if (!status) {
    std::cout << L"Unable to get system handles: " << std::endl;
    return 1;
  }

  auto handleInfo = reinterpret_cast<PSYSTEM_HANDLE_INFORMATION_EX>(handleInfoBuf.get());
//     auto const guard_process_dup_handle = scope_guard::create(
//         [handleInfo]() { CloseHandle(handleInfo); });

  for (i = 0; i < handleInfo->NumberOfHandles; i++) {
    handle = handleInfo->Handles[i];
    // std::cout << handle.UniqueProcessId << " == "<< std::endl;

    processHandle = OpenProcess(PROCESS_DUP_HANDLE, FALSE, static_cast<DWORD>(handle.UniqueProcessId));
    if (!processHandle) {
      continue;
    }
    // GUARD, close processHandle
    if (_NtDuplicateObject(processHandle, reinterpret_cast<HANDLE>(handle.HandleValue), GetCurrentProcess(), &processDupHandle, GENERIC_READ, 0, 0) != STATUS_SUCCESS) {
      continue;
    }
    // GUARD, close processDupHandle

    ObjectInfoTuple objInfo = std::make_tuple("", "");

    if (!getHandleInfo(processDupHandle, _NtQueryObject, objInfo)) {
      continue;

    }

    auto handle_attributes = getHandleAttributes(handle.GrantedAccess);

    std::cout << "===" << std::endl;
    std::cout << handle_attributes << std::endl;;
    std::cout << std::get<0>(objInfo) << std::endl;;
    std::cout << std::get<1>(objInfo) << std::endl;;

  }
//     // Build a row from the provided handle informations
//     Row r;

//     r["pid"] = BIGINT(handle.UniqueProcessId);
//     r["object_type"] = std::get<0>(objInfo);
//     r["object_name"] = std::get<1>(objInfo);
//     r["attributes"] = handle_attributes;
//     rows.push_back(r);
//   }

  return 0;
}
