#include "DispatchIo.h"
#include"vector.hpp"

extern void RestoreHook();
extern std::vector<void*>* gAccessRoutine;

void DriverUnload(PDRIVER_OBJECT)
{
	RestoreHook();
	if (gAccessRoutine)
		delete gAccessRoutine;
	DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,"bypass exit!\n");
}

NTSTATUS DisPatchIoControl(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	NTSTATUS st = STATUS_SUCCESS;

	return st;
}