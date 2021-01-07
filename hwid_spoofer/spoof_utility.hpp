#pragma once
#include <ntifs.h>
#include <ntdddisk.h>
#include <scsi.h>
#include <ntddscsi.h>
#include "serial_generator.hpp"
#include "stealth_import.hpp"

struct request_t
{
	PIO_COMPLETION_ROUTINE old_routine;
	PVOID old_context;
	ULONG output_length;
	PVOID system_buffer;
};

struct IDINFO
{
	USHORT	wGenConfig;
	USHORT	wNumCyls;
	USHORT	wReserved;
	USHORT	wNumHeads;
	USHORT	wBytesPerTrack;
	USHORT	wBytesPerSector;
	USHORT	wNumSectorsPerTrack;
	USHORT	wVendorUnique[ 3 ];
	CHAR	sSerialNumber[ 20 ];
	USHORT	wBufferType;
	USHORT	wBufferSize;
	USHORT	wECCSize;
	CHAR	sFirmwareRev[ 8 ];
	CHAR	sModelNumber[ 40 ];
	USHORT	wMoreVendorUnique;
	USHORT	wDoubleWordIO;
	struct
	{
		USHORT	Reserved : 8;
		USHORT	DMA : 1;
		USHORT	LBA : 1;
		USHORT	DisIORDY : 1;
		USHORT	IORDY : 1;
		USHORT	SoftReset : 1;
		USHORT	Overlap : 1;
		USHORT	Queue : 1;
		USHORT	InlDMA : 1;
	} wCapabilities;
	USHORT	wReserved1;
	USHORT	wPIOTiming;
	USHORT	wDMATiming;
	struct
	{
		USHORT	CHSNumber : 1;
		USHORT	CycleNumber : 1;
		USHORT	UnltraDMA : 1;
		USHORT	Reserved : 13;
	} wFieldValidity;
	USHORT	wNumCurCyls;
	USHORT	wNumCurHeads;
	USHORT	wNumCurSectorsPerTrack;
	USHORT	wCurSectorsLow;
	USHORT	wCurSectorsHigh;
	struct
	{
		USHORT	CurNumber : 8;
		USHORT	Multi : 1;
		USHORT	Reserved : 7;
	} wMultSectorStuff;
	ULONG	dwTotalSectors;
	USHORT	wSingleWordDMA;
	struct
	{
		USHORT	Mode0 : 1;
		USHORT	Mode1 : 1;
		USHORT	Mode2 : 1;
		USHORT	Reserved1 : 5;
		USHORT	Mode0Sel : 1;
		USHORT	Mode1Sel : 1;
		USHORT	Mode2Sel : 1;
		USHORT	Reserved2 : 5;
	} wMultiWordDMA;
	struct
	{
		USHORT	AdvPOIModes : 8;
		USHORT	Reserved : 8;
	} wPIOCapacity;
	USHORT	wMinMultiWordDMACycle;
	USHORT	wRecMultiWordDMACycle;
	USHORT	wMinPIONoFlowCycle;
	USHORT	wMinPOIFlowCycle;
	USHORT	wReserved69[ 11 ];
	struct
	{
		USHORT	Reserved1 : 1;
		USHORT	ATA1 : 1;
		USHORT	ATA2 : 1;
		USHORT	ATA3 : 1;
		USHORT	ATA4 : 1;
		USHORT	ATA5 : 1;
		USHORT	ATA6 : 1;
		USHORT	ATA7 : 1;
		USHORT	ATA8 : 1;
		USHORT	ATA9 : 1;
		USHORT	ATA10 : 1;
		USHORT	ATA11 : 1;
		USHORT	ATA12 : 1;
		USHORT	ATA13 : 1;
		USHORT	ATA14 : 1;
		USHORT	Reserved2 : 1;
	} wMajorVersion;
	USHORT	wMinorVersion;
	USHORT	wReserved82[ 6 ];
	struct
	{
		USHORT	Mode0 : 1;
		USHORT	Mode1 : 1;
		USHORT	Mode2 : 1;
		USHORT	Mode3 : 1;
		USHORT	Mode4 : 1;
		USHORT	Mode5 : 1;
		USHORT	Mode6 : 1;
		USHORT	Mode7 : 1;
		USHORT	Mode0Sel : 1;
		USHORT	Mode1Sel : 1;
		USHORT	Mode2Sel : 1;
		USHORT	Mode3Sel : 1;
		USHORT	Mode4Sel : 1;
		USHORT	Mode5Sel : 1;
		USHORT	Mode6Sel : 1;
		USHORT	Mode7Sel : 1;
	} wUltraDMA;
	USHORT	wReserved89[ 167 ];
};

NTSTATUS process_storage_query( PDEVICE_OBJECT device_object, PIRP irp_ptr, PVOID context )
{
	if ( !context )
		return STATUS_SUCCESS;

	const auto request = static_cast< request_t* >( context );

	const auto buffer_len = request->output_length;
	const auto buffer = static_cast< PSTORAGE_DEVICE_DESCRIPTOR >( request->system_buffer );

	const auto routine = request->old_routine;
	const auto o_context = request->old_context;

	ExFreePool( context );

	do
	{
		if ( buffer_len < FIELD_OFFSET( STORAGE_DEVICE_DESCRIPTOR, RawDeviceProperties ) )
			break;

		if ( !buffer->SerialNumberOffset )
			break;

		if ( buffer_len < FIELD_OFFSET( STORAGE_DEVICE_DESCRIPTOR, RawDeviceProperties ) + buffer->RawPropertiesLength
			 || buffer->SerialNumberOffset < FIELD_OFFSET( STORAGE_DEVICE_DESCRIPTOR, RawDeviceProperties )
			 || buffer->SerialNumberOffset >= buffer_len
		   )
			break;

		spoof_serial( reinterpret_cast< char* >( buffer ) + buffer->SerialNumberOffset );
	} while ( false );

	if ( irp_ptr->StackCount > 1u && routine )
		return routine( device_object, irp_ptr, o_context );

	return STATUS_SUCCESS;
}

NTSTATUS process_smart_query( [[maybe_unused]] PDEVICE_OBJECT device_object, PIRP irp_ptr, PVOID context )
{
	if ( !context )
		return STATUS_SUCCESS;

	const auto request = static_cast< request_t* >( context );

	const auto buffer_len = request->output_length;
	const auto buffer = static_cast< PSENDCMDOUTPARAMS >( request->system_buffer );

	ExFreePool( context );

	do
	{
		if ( buffer_len < FIELD_OFFSET( SENDCMDOUTPARAMS, bBuffer )
			 || FIELD_OFFSET( SENDCMDOUTPARAMS, bBuffer ) + buffer->cBufferSize > buffer_len
			 || buffer->cBufferSize < sizeof( IDINFO ) 
		   )
			break;

		const auto parameters = reinterpret_cast< PSENDCMDOUTPARAMS >( buffer->bBuffer + sizeof( SRB_IO_CONTROL ) );
		const auto actual_info = reinterpret_cast< IDINFO* >( parameters->bBuffer );

		spoof_serial( reinterpret_cast< char* >( actual_info->sSerialNumber ) );
	} while ( false );

	return irp_ptr->IoStatus.Status;
}

void process_query( PIRP irp_ptr, PIO_STACK_LOCATION stack_ptr, PIO_COMPLETION_ROUTINE routine )
{
	stack_ptr->Control = 0u;
	stack_ptr->Control |= SL_INVOKE_ON_SUCCESS;

	const auto old_context = stack_ptr->Context;
	stack_ptr->Context = ST_FN( ExAllocatePool )( PagedPool, sizeof( request_t ) );

	if ( !stack_ptr->Context )
		return;

	const auto request = static_cast< request_t* >( stack_ptr->Context );

	request->old_context = old_context;
	request->old_routine = stack_ptr->CompletionRoutine;
	request->output_length = stack_ptr->Parameters.DeviceIoControl.OutputBufferLength;
	request->system_buffer = irp_ptr->AssociatedIrp.SystemBuffer;

	stack_ptr->CompletionRoutine = routine;
}