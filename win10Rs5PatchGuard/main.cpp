#include "stdafx.h"
#include "DispatchIo.h"

#include"pg.h"


extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT driverObject, PUNICODE_STRING registPath)
{
	driverObject->DriverUnload = DriverUnload;

	BypassStart();

	return STATUS_SUCCESS;
}