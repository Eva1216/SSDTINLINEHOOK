#include "SSDTINLINEHOOK_FF15.h"

extern PSYSTEM_SERVICE_DESCRIPTOR_TABLE KeServiceDescriptorTable;
extern POBJECT_TYPE* PsProcessType;
extern POBJECT_TYPE* IoFileObjectType;
PVOID* __ServiceTableBase = NULL;
LPFN_OBGETOBJECTTYPE __ObGetObjectType = NULL;
LPFN_NTOPENPROCESS __NtOpenProcess = NULL;
UCHAR*   __OriginalNtOpenProcessCode = NULL;
UCHAR*   __TrampolineCode = NULL;
ULONG    __PatchedCodeLength = 6;
PVOID pProxyFunction = 0;
UCHAR JumpCode[6] = { 0xff,0x15,0x00,0x00,0x00,0x00 };     //FF 15 XX XX XX XX
UCHAR JumpBackCode[6] = { 0xff,0x15,0x00,0x00,0x00,0x00 }; //FF 15 XX XX XX XX
PVOID v1 = NULL;
PVOID v2 = NULL;
NTSTATUS SSDTInlineHook(PVOID OriginalAddress, PVOID FakeAddress, ULONG PatchedCodeLength);
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegisterPath)
{

	UNREFERENCED_PARAMETER(RegisterPath);

	ULONG	NtOpenProcessIndex = 0;
	CHAR    ZwFunctionName[] = "ZwOpenProcess";


	NTSTATUS  Status = STATUS_UNSUCCESSFUL;



	DbgPrint("DriverEntry()\r\n");

	//��������ж������
	DriverObject->DriverUnload = DriverUnload;


	//��ȡSSDT
	__ServiceTableBase = (PVOID*)KeServiceDescriptorTable->ServiceTableBase;

	if (__ServiceTableBase == NULL)
	{
		return Status;
	}
	//��ȡNtXXX����������
	if (!NT_SUCCESS(SeGetSSDTFunctionIndexByFunctionName(ZwFunctionName,
		&NtOpenProcessIndex)))
	{
		return Status;
	}
	__NtOpenProcess = (LPFN_NTOPENPROCESS)(__ServiceTableBase[NtOpenProcessIndex]);
	if (__NtOpenProcess == NULL)
	{
		return Status;
	}
 
	v1 = (PVOID)&FakeNtOpenProcess;
	 //HookSSDTFunctionByPush( __NtOpenProcess);
	SSDTInlineHook(__NtOpenProcess, FakeNtOpenProcess, __PatchedCodeLength);
	return STATUS_SUCCESS;
}


NTSTATUS SSDTInlineHook(PVOID OriginalAddress, PVOID FakeAddress, ULONG PatchedCodeLength)
{
	PUCHAR v3 = NULL;
	UCHAR v2[] = "\xe9\x00\x00\x00\x00";
 

	//�ó�Ա���ڻָ�
	__OriginalNtOpenProcessCode = (UCHAR*)ExAllocatePool(NonPagedPool, PatchedCodeLength);//6

	if (__OriginalNtOpenProcessCode == NULL)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	OnEnableWrite();
	memcpy(__OriginalNtOpenProcessCode, (PVOID)OriginalAddress, PatchedCodeLength);
	OnDisableWrite();



	__TrampolineCode = (UCHAR*)ExAllocatePool(NonPagedPool, (PatchedCodeLength + 5));
	if (__TrampolineCode == NULL)
	{

		if (__OriginalNtOpenProcessCode != NULL)
		{
			ExFreePool(__OriginalNtOpenProcessCode);
			__OriginalNtOpenProcessCode = NULL;
		}
		return STATUS_INSUFFICIENT_RESOURCES;
	}



	RtlFillMemory(__TrampolineCode, PatchedCodeLength + 5, 0x90);  //NOP
																   //__TrampolineCode[0x90 0x90 0x90 0x90 0x90 0x90 0x90 0x90 0x90 0x90]


	memcpy((PUCHAR)__TrampolineCode, __OriginalNtOpenProcessCode, PatchedCodeLength);


	*(ULONG *)((ULONG)JumpCode + 2) = &v1;
	
	v3 = (PUCHAR)OriginalAddress + PatchedCodeLength;


	*((ULONG*)&v2[1]) = (PUCHAR)v3 - ((PUCHAR)__TrampolineCode + 6 + 5);



	memcpy((PUCHAR)__TrampolineCode + PatchedCodeLength, v2, 5);

	OnEnableWrite();
	memcpy((PVOID)OriginalAddress, JumpCode, PatchedCodeLength);
	OnDisableWrite();
	return STATUS_SUCCESS;
}

//PVOID HookSSDTFunctionByPush(PVOID pSourceFunction)
//{
//	DbgBreakPoint();
//
//	if (!pSourceFunction)return NULL;
//
//	*(ULONG *)((ULONG)JumpCode + 2) = &v1;
//
//
//
//	PUCHAR pOpCode;
//	ULONG BackupLength = 0;
//
//
//	while (BackupLength < 6)
//	{
//		BackupLength += GetFunctionCodeSize((PVOID)((ULONG)pSourceFunction + BackupLength), &pOpCode);
//	}
//	pProxyFunction = ExAllocatePool(NonPagedPool, (BackupLength + 6));
//
//	if (!pProxyFunction)return NULL;
//
//
//	v2 = (ULONG)pSourceFunction + BackupLength;
//	*(ULONG *)((ULONG)JumpBackCode + 2) = &v2;
//	OnEnableWrite();
//	RtlCopyMemory(pProxyFunction, pSourceFunction, BackupLength);
//	RtlCopyMemory((PVOID)((ULONG)pProxyFunction + BackupLength), JumpBackCode, 6);
//
//	OnDisableWrite();
//
//
//
//	OnEnableWrite();
//	RtlCopyMemory(pSourceFunction, JumpCode, 6);
//	OnDisableWrite();
//
//
//
//
//	return pProxyFunction;
//
//
//}



 
VOID SSDTUninlineHook(PVOID OriginalAddress, PUCHAR OriginalCode, ULONG PatchedCodeLength)
{
	OnEnableWrite();
	memcpy(OriginalAddress, OriginalCode, PatchedCodeLength);
	OnDisableWrite();
}
NTSTATUS SeGetSSDTFunctionIndexByFunctionName(CHAR* ZwFunctionName, ULONG* NtFunctionIndex)
{
	/*
	0:004> u zwopenProcess
	ntdll!ZwOpenProcess:
	77845dc8 b8be000000      mov     eax,0BEh
	77845dcd ba0003fe7f      mov     edx,offset SharedUserData!SystemCallStub (7ffe0300)
	77845dd2 ff12            call    dword ptr [edx]
	77845dd4 c21000          ret     10h
	77845dd7 90              nop

	*/

	ULONG     Offset = 1;
	WCHAR     FileFullPath[] = L"\\SystemRoot\\System32\\ntdll.dll";
	NTSTATUS  Status = STATUS_SUCCESS;
	SIZE_T    MappedFileSize = 0;
	PVOID     MappedFileVA = NULL;
	PIMAGE_NT_HEADERS  ImageNtHeaders = NULL;
	PIMAGE_EXPORT_DIRECTORY ImageExoportDirectory = NULL;
	ULONG*    AddressOfFunctions = NULL;
	ULONG*    AddressOfNames = NULL;
	USHORT*   AddressOfNameOrdinals = NULL;
	CHAR*     FunctionName = NULL;
	ULONG     i = 0;
	PUCHAR    FunctionAddress = 0;

	//��Ntdll.dll�ļ�ӳ�䵽ϵͳ�ռ���
	Status = SeMappingPEFileInRing0Space(FileFullPath, &MappedFileVA, &MappedFileSize);
	if (!NT_SUCCESS(Status))
	{
		return Status;
	}
	else
	{
		__try {
			//ͨ��DosHead���NtHeaders
			ImageNtHeaders = RtlImageNtHeader(MappedFileVA);
			if (ImageNtHeaders && ImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)
			{
				ImageExoportDirectory = (IMAGE_EXPORT_DIRECTORY*)((ULONG_PTR)MappedFileVA +
					ImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);



				AddressOfFunctions = (ULONG*)((ULONG_PTR)MappedFileVA + ImageExoportDirectory->AddressOfFunctions);
				AddressOfNames = (ULONG*)((ULONG_PTR)MappedFileVA + ImageExoportDirectory->AddressOfNames);
				AddressOfNameOrdinals = (USHORT*)((ULONG_PTR)MappedFileVA + ImageExoportDirectory->AddressOfNameOrdinals);

				for (i = 0; i < ImageExoportDirectory->NumberOfNames; i++)
				{
					FunctionName = (char*)((ULONG_PTR)MappedFileVA + AddressOfNames[i]);   //��ú�������
					if (_stricmp(FunctionName, ZwFunctionName) == 0)
					{
						FunctionAddress = (PUCHAR)((ULONG_PTR)MappedFileVA +
							AddressOfFunctions[AddressOfNameOrdinals[i]]);


						*NtFunctionIndex = *(ULONG*)(FunctionAddress + Offset);
						break;
					}
				}
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			;
		}
	}
	ZwUnmapViewOfSection(NtCurrentProcess(), MappedFileVA);


	if (*NtFunctionIndex == -1)
	{
		Status = STATUS_UNSUCCESSFUL;
	}

	return Status;
}
NTSTATUS
SeMappingPEFileInRing0Space(WCHAR* FileFullPath, OUT PVOID* MappedFileVA, PSIZE_T MappedFileSize)
{
	UNICODE_STRING    v1;
	OBJECT_ATTRIBUTES ObjectAttributes;
	NTSTATUS          Status = STATUS_SUCCESS;
	IO_STATUS_BLOCK   IoStatusBlock;

	HANDLE   FileHandle = NULL;
	HANDLE   SectionHandle = NULL;

	if (!FileFullPath || !MappedFileVA)
	{
		return STATUS_UNSUCCESSFUL;
	}
	RtlInitUnicodeString(&v1, FileFullPath);
	InitializeObjectAttributes(&ObjectAttributes,
		&v1,
		OBJ_CASE_INSENSITIVE,
		NULL,
		NULL
	);
	//����ļ����
	Status = ZwCreateFile(&FileHandle,
		SYNCHRONIZE,
		&ObjectAttributes,
		&IoStatusBlock,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ,
		FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0);
	if (!NT_SUCCESS(Status))
	{

		return Status;
	}

	//����һ��ӳ�����
	ObjectAttributes.ObjectName = NULL;
	Status = ZwCreateSection(&SectionHandle,
		SECTION_QUERY | SECTION_MAP_READ,
		&ObjectAttributes,
		NULL,
		PAGE_WRITECOPY,             //д����
		SEC_IMAGE,                  //ָʾ�ڴ����
		FileHandle
	);
	ZwClose(FileHandle);
	if (!NT_SUCCESS(Status))
	{
		return Status;
	}
	Status = ZwMapViewOfSection(SectionHandle,
		NtCurrentProcess(),    //ӳ�䵽��ǰ���̵��ڴ�ռ���
		MappedFileVA,
		0,
		0,
		0,
		MappedFileSize,
		ViewUnmap,
		0,
		PAGE_WRITECOPY
	);
	ZwClose(SectionHandle);
	if (!NT_SUCCESS(Status))
	{
		return Status;
	}

	return Status;
}

NTSTATUS
FakeNtOpenProcess(
	OUT PHANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PCLIENT_ID ClientId OPTIONAL
)
{
	__try
	{
		//�������±�����
		PEPROCESS  EProcess = PsGetCurrentProcess();
		if (EProcess != NULL&&MmIsAddressValid(EProcess) && SeIsRealProcess(EProcess) == TRUE)
		{
			//ͨ��EProcess��ý������� 
			WCHAR  ProcessFullPath[MAX_PATH] = { 0 };
			if (SeGetProcessFullPathByEProcess(EProcess, ProcessFullPath, MAX_PATH) == TRUE)
			{
				DbgPrint("%S\r\n", ProcessFullPath);
				if (wcsstr(ProcessFullPath, L"1.exe") != 0)
				{
					return STATUS_ACCESS_DENIED;  //������
				}
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return GetExceptionCode();
	}

	if (__TrampolineCode != NULL)
	{
		return ((LPFN_NTOPENPROCESS)__TrampolineCode)(ProcessHandle, DesiredAccess, ObjectAttributes,
			ClientId);  //������
	}
}
BOOLEAN SeGetProcessFullPathByEProcess(PEPROCESS EProcess, WCHAR* ProcessFullPath, ULONG ProcessFullPathLength)
{
	BOOLEAN IsOk = FALSE;
	KPROCESSOR_MODE PreviousMode;
	HANDLE ProcessHandle = NULL;
	ULONG HandleAttributes = 0;


	PreviousMode = PsGetCurrentThreadPreviousMode();
	//�������4�ı���  0x80000004   0x00000004
	HandleAttributes = (PreviousMode == KernelMode ? OBJ_KERNEL_HANDLE : 0);
	//ͨ���������ö�����
	if (NT_SUCCESS(ObOpenObjectByPointer(EProcess, HandleAttributes, NULL, PROCESS_QUERY_INFORMATION,
		*PsProcessType, PreviousMode, &ProcessHandle)))
	{
		PVOID BufferData = NULL;
		ULONG ReturnLength = 0;

		if (ZwQueryInformationProcess(ProcessHandle, ProcessImageFileName,
			BufferData, ReturnLength, &ReturnLength) == STATUS_INFO_LENGTH_MISMATCH)
		{
			if (BufferData = ExAllocatePool(PagedPool, ReturnLength))
			{
				if (NT_SUCCESS(ZwQueryInformationProcess(ProcessHandle,
					ProcessImageFileName, BufferData, ReturnLength, &ReturnLength)))
				{
					HANDLE FileHandle = NULL;
					OBJECT_ATTRIBUTES ObjectAttributes;
					IO_STATUS_BLOCK IoStatusBlock;

					InitializeObjectAttributes(&ObjectAttributes, (PUNICODE_STRING)BufferData,
						OBJ_CASE_INSENSITIVE | HandleAttributes, NULL, NULL);
					if (NT_SUCCESS(ZwOpenFile(&FileHandle, FILE_READ_ATTRIBUTES | SYNCHRONIZE,
						&ObjectAttributes, &IoStatusBlock, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT)))
					{
						PFILE_OBJECT FileObject;

						//ͨ�������ö���
						if (NT_SUCCESS(ObReferenceObjectByHandle(FileHandle, FILE_READ_ATTRIBUTES,
							*IoFileObjectType, PreviousMode, (PVOID*)&FileObject, NULL)))
						{
							POBJECT_NAME_INFORMATION ObjetNameInfo;

							//ͨ���ļ��������ļ�����·��
							if (NT_SUCCESS(IoQueryFileDosDeviceName(FileObject, &ObjetNameInfo)))
							{

								if (((UNICODE_STRING*)ObjetNameInfo)->MaximumLength < ProcessFullPathLength)
								{
									memcpy(ProcessFullPath, ((UNICODE_STRING*)ObjetNameInfo)->Buffer,
										((UNICODE_STRING*)ObjetNameInfo)->MaximumLength);
								}
								else
								{
									memcpy(ProcessFullPath, ((UNICODE_STRING*)ObjetNameInfo)->Buffer, ProcessFullPathLength);
								}
								IsOk = TRUE;
							}
							ObDereferenceObject(FileObject);
						}
						ZwClose(FileHandle);
					}
				}
				ExFreePool(BufferData);
			}
		}
		ZwClose(ProcessHandle);
	}
	return IsOk;
}
BOOLEAN SeIsRealProcess(PEPROCESS EProcess)
{
	//�鿴EProcess�Ƿ���н��̶�������
	ULONG_PTR    ObjectType;
	ULONG_PTR    ObjectTypeAddress;
	ULONG_PTR    ProcessType = ((ULONG_PTR)*PsProcessType);   //ϵͳ��һģ�鵼����ȫ�ֱ���
															  /*
															  dd PsProcessType
															  849aa104  878dcd28
															  */

															  //��ϵͳ�еĵ�һ��ģ��(ntkrnlpa.exe)�еĵ������л�ú�����ַ

	if (__ObGetObjectType == NULL)
	{
		UNICODE_STRING v1;
		RtlInitUnicodeString(&v1, L"ObGetObjectType");
		__ObGetObjectType = (LPFN_OBGETOBJECTTYPE)MmGetSystemRoutineAddress(&v1);
	}
	/*
	0: kd> dd __ObGetObjectType
	a8189008  84a99b68 00000000 00000000 00000000
	0: kd> u  84a99b68
	nt!ObGetObjectType:
	84a99b68 8bff            mov     edi,edi
	84a99b6a 55              push    ebp
	84a99b6b 8bec            mov     ebp,esp
	84a99b6d 8b4508          mov     eax,dword p
	*/
	if (ProcessType && EProcess && MmIsAddressValid((PVOID)(EProcess)))
	{

		ObjectType = __ObGetObjectType((PVOID)EProcess);
		if (ObjectType &&
			ProcessType == ObjectType)
		{
			//��ǰEProcess��һ����Ч�Ľ���
			return TRUE;
		}


	}
	return FALSE;
}
void DriverUnload(PDRIVER_OBJECT DriverObject)
{
	SSDTUninlineHook(__NtOpenProcess, __OriginalNtOpenProcessCode, __PatchedCodeLength);


	if (__OriginalNtOpenProcessCode != NULL)
	{
		ExFreePool(__OriginalNtOpenProcessCode);
		__OriginalNtOpenProcessCode = NULL;
	}

	if (__TrampolineCode != NULL)
	{
		ExFreePool(__TrampolineCode);
		__TrampolineCode = NULL;
	}
	DbgPrint("DriverUnload()\r\n");
}
//�ر�д����
VOID
OnEnableWrite()
{
	__try
	{
		_asm
		{
			cli                    //��ֹ�жϷ���
			mov eax, cr0
			and eax, not 10000h    //cr0�Ĵ����е�17λ WPλ 
			mov cr0, eax
		}
	}
	__except (1)
	{

	}
}

//�ָ�д����
VOID
OnDisableWrite()
{
	__try
	{
		_asm
		{
			mov eax, cr0
			or eax, 10000h
			mov cr0, eax

			sti                    //�����жϷ��� 
		}
	}
	__except (1)
	{

	}
}
