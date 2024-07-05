#include <ntddk.h>
#include "RevealCommon.h"

#define DRIVER_PREFIX "Reveal: "

void RevealUnload(PDRIVER_OBJECT DriverObject);
NTSTATUS RevealCreateClose(PDEVICE_OBJECT, PIRP Irp);
NTSTATUS RevealDeviceControl(PDEVICE_OBJECT, PIRP Irp);
NTSTATUS CompleteRequest(PIRP Irp, NTSTATUS status = STATUS_SUCCESS,
	ULONG_PTR info = 0);

extern "C" 
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING)
{
	// Set unload function
	DriverObject->DriverUnload = RevealUnload;

	// Set supported dispatches	
	DriverObject->MajorFunction[IRP_MJ_CREATE] = RevealCreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = RevealCreateClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = RevealDeviceControl;

	UNICODE_STRING name = RTL_CONSTANT_STRING(L"\\Device\\Reveal");
	PDEVICE_OBJECT devObj;

	NTSTATUS status = IoCreateDevice(DriverObject, 0, &name, FILE_DEVICE_UNKNOWN, 0, FALSE, &devObj);

	if (!NT_SUCCESS(status))
	{
		KdPrint((DRIVER_PREFIX"Failed to create device: 0x%X\n", status));
		return status;
	}

	// Create symlink for user space use
	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\Reveal");
	status = IoCreateSymbolicLink(&symLink, &name);
	if (!NT_SUCCESS(status))
	{
		KdPrint((DRIVER_PREFIX"Failed to create symbolic link: 0x%X\n", status));
		IoDeleteDevice(devObj);
		return status;
	}

	KdPrint((DRIVER_PREFIX"Successfully Created device\n"));
	return STATUS_SUCCESS;
}

void RevealUnload(PDRIVER_OBJECT DriverObject)
{
	KdPrint((DRIVER_PREFIX"Unloading\n"));
	// Delete device
	IoDeleteDevice(DriverObject->DeviceObject);
	// Delete symbolic link
	UNICODE_STRING symName = RTL_CONSTANT_STRING(L"\\??\\Reveal");
	IoDeleteSymbolicLink(&symName);
}
NTSTATUS RevealCreateClose(PDEVICE_OBJECT, PIRP Irp)
{
	KdPrint((DRIVER_PREFIX"Create/Close\n"));
	// Just complete request
	return CompleteRequest(Irp);
}

NTSTATUS RevealDeviceControl(PDEVICE_OBJECT, PIRP Irp)
{
	KdPrint((DRIVER_PREFIX"Device control\n"));
	// Get stack pointer for the irp
	PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
	
	// Get device io control
	auto& dic = irpSp->Parameters.DeviceIoControl;
	NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
	auto len = 0;

	switch (dic.IoControlCode)
	{
		case IOCTL_OPEN_PROCESS :
			KdPrint((DRIVER_PREFIX"Open process case\n"));
			// Validate input output buffers size
			if (dic.InputBufferLength < sizeof(OpenProcessData) ||
				dic.OutputBufferLength < sizeof(HANDLE))
			{
				status = STATUS_BUFFER_TOO_SMALL;
				KdPrint((DRIVER_PREFIX"Buffer too small\n"));
				break;
			}

			// Get the input buffer
			OpenProcessData* data = (OpenProcessData*)Irp->AssociatedIrp.SystemBuffer;
			if (data == nullptr)
			{
				status = STATUS_INVALID_PARAMETER;
				KdPrint((DRIVER_PREFIX"Failed accessing system buffer\n"));
				break;
			}

			HANDLE ProcessHandle;
			ACCESS_MASK DesiredAccess = data->Access;
			OBJECT_ATTRIBUTES ObjectAttributes;
			CLIENT_ID ClientId;

			InitializeObjectAttributes(&ObjectAttributes,NULL,0,NULL,NULL);
			ClientId.UniqueThread = NULL;
			ClientId.UniqueProcess = UlongToHandle(data->ProcessId);

			// Open process
			status = ZwOpenProcess(&ProcessHandle, DesiredAccess, &ObjectAttributes, &ClientId);

			if (NT_SUCCESS(status))
			{
				KdPrint((DRIVER_PREFIX"Successfully got process information\n"));
				len = sizeof(ProcessHandle);
				memcpy(data, &ProcessHandle, sizeof(ProcessHandle));
			}
			break;

	}

	return CompleteRequest(Irp, status, len);

}

NTSTATUS CompleteRequest(PIRP Irp, NTSTATUS status, ULONG_PTR info)
{
	KdPrint((DRIVER_PREFIX"CompleteIo\n"));
	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = info;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}