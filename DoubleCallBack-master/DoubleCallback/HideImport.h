//Setup Import Defines
#define ImpSet(a) a##Fn = (a##Def)EPtr(GetProcAdress(KBase, E(#a)));
#define ImpDef(a) using a##Def = decltype(&a); a##Def a##Fn = nullptr;
#define ImpCall(a, ...) ((a##Def)EPtr(a##Fn))(__VA_ARGS__)

// decltype 用于获取 &IoIs32bitProcess 的类型
// using IoIs32bitProcessDef = decltype(&IoIs32bitProcess); 
// IoIs32bitProcessDef IoIs32bitProcessFn = nullptr;
ImpDef(IoIs32bitProcess);
ImpDef(ZwProtectVirtualMemory);
ImpDef(PsGetProcessWow64Process);
ImpDef(KeRegisterBoundCallback);
ImpDef(KeDeregisterBoundCallback);
ImpDef(ZwQueryObject);
ImpDef(ExAllocatePoolWithTag);
ImpDef(ExFreePoolWithTag);
ImpDef(IoGetCurrentProcess);
ImpDef(KeAttachProcess);
ImpDef(KeDelayExecutionThread);
ImpDef(KeDetachProcess);
ImpDef(KeEnterGuardedRegion);
ImpDef(KeLeaveGuardedRegion);
ImpDef(KeQueryAuxiliaryCounterFrequency);
ImpDef(KeUserModeCallback);
ImpDef(MmIsAddressValid);
ImpDef(ObfDereferenceObject);
ImpDef(PsAcquireProcessExitSynchronization);
ImpDef(PsGetProcessPeb);
ImpDef(PsLookupProcessByProcessId);
ImpDef(PsLookupThreadByThreadId);
ImpDef(PsReleaseProcessExitSynchronization);
ImpDef(RtlCreateUserThread);
ImpDef(ZwAllocateVirtualMemory);
ImpDef(ZwClose);
ImpDef(ZwFreeVirtualMemory);
ImpDef(ZwQuerySystemInformation);
ImpDef(ZwQueryVirtualMemory); 
ImpDef(MmSecureVirtualMemory);
ImpDef(ZwSetInformationVirtualMemory);
ImpDef(MmGetVirtualForPhysical);
ImpDef(PsCreateSystemThread);
ImpDef(PsGetCurrentThreadId);
ImpDef(IoAllocateMdl);
ImpDef(MmBuildMdlForNonPagedPool);
ImpDef(MmMapLockedPages);
ImpDef(MmUnmapLockedPages);
ImpDef(IoFreeMdl);