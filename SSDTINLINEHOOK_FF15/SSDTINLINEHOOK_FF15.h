#pragma once

#include <fltKernel.h>
#include <ntimage.h>
#include "Common.h"


#define  SEC_IMAGE 0x1000000
#define  MAX_PATH  260
#define PROCESS_QUERY_INFORMATION (0x0400) 
typedef struct _SYSTEM_SERVICE_DESCRIPTOR_TABLE_ {
	PVOID  		ServiceTableBase;
	PVOID  		ServiceCounterTableBase;
	ULONG_PTR  	NumberOfServices;
	PVOID  		ParameterTableBase;
}SYSTEM_SERVICE_DESCRIPTOR_TABLE, *PSYSTEM_SERVICE_DESCRIPTOR_TABLE;


typedef
NTSTATUS
(__stdcall *LPFN_NTOPENPROCESS) (
	OUT PHANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PCLIENT_ID ClientId OPTIONAL
	);



extern
CCHAR
PsGetCurrentThreadPreviousMode(
	VOID);

extern
NTSTATUS ZwQueryInformationProcess(HANDLE ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation,
	ULONG ProcessInformationLength, PULONG ReturnLength);

extern
NTSYSAPI
PIMAGE_NT_HEADERS
NTAPI
RtlImageNtHeader(PVOID ModuleBase);


typedef
ULONG_PTR
(*LPFN_OBGETOBJECTTYPE)(PVOID ObjectBody);
NTSTATUS SSDTInlineHook(PVOID OriginalAddress, PVOID FakeAddress, ULONG PatchedCodeLength);
VOID SSDTUninlineHook(PVOID OriginalAddress, PUCHAR OriginalCode, ULONG PatchedCodeLength);
NTSTATUS SeGetSSDTFunctionIndexByFunctionName(CHAR* ZwFunctionName, ULONG* NtFunctionIndex);
BOOLEAN SeIsRealProcess(PEPROCESS EProcess);
NTSTATUS
SeMappingPEFileInRing0Space(WCHAR* FileFullPath, OUT PVOID* MappedFileVA, PSIZE_T MappedFileSize);
BOOLEAN SeGetProcessFullPathByEProcess(PEPROCESS EProcess, WCHAR* ProcessFullPath, ULONG ProcessFullPathLength);
NTSTATUS
FakeNtOpenProcess(
	OUT PHANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PCLIENT_ID ClientId OPTIONAL
);
void DriverUnload(PDRIVER_OBJECT DriverObject);
VOID
OnDisableWrite();
VOID
OnEnableWrite();

PVOID HookSSDTFunctionByPush(PVOID pSourceFunction);
