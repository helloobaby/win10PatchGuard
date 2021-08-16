#include"stdafx.h"
void DriverUnload(PDRIVER_OBJECT);

//IRP_MJ_DEVICE_CONTROL
NTSTATUS DisPatchIoControl(PDEVICE_OBJECT pDevObj, PIRP pIrp);

//IRP_MJ_CREATE
NTSTATUS DisPatchIoCreate(PDEVICE_OBJECT pDevObj, PIRP pIrp);




