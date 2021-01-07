#include <ntifs.h>
#include "shell_coder.hpp"
#include "search_utility.hpp"
#include "general_utility.hpp"
#include "spoof_utility.hpp"
#include "registry_spoofer.hpp"

PDRIVER_DISPATCH original_dispatch = nullptr;
PDRIVER_DISPATCH original_dispatch_scsi = nullptr;

NTSTATUS driver_dispatch( PDEVICE_OBJECT device_object, PIRP irp_ptr )
{
	const auto stack_ptr = irp_ptr->Tail.Overlay.CurrentStackLocation;

	switch ( stack_ptr->Parameters.DeviceIoControl.IoControlCode )
	{
		case IOCTL_STORAGE_QUERY_PROPERTY:
			{
				const auto query = static_cast< PSTORAGE_PROPERTY_QUERY >( irp_ptr->AssociatedIrp.SystemBuffer );

				if ( query->PropertyId == StorageDeviceProperty )
					process_query( irp_ptr, stack_ptr, &process_storage_query );

				break;
			}
		default:break;
	}

	return original_dispatch( device_object, irp_ptr );
}

NTSTATUS driver_dispatch_scsi( PDEVICE_OBJECT device_object, PIRP irp_ptr )
{
	const auto stack_ptr = irp_ptr->Tail.Overlay.CurrentStackLocation;

	switch ( stack_ptr->Parameters.DeviceIoControl.IoControlCode )
	{
		case IOCTL_SCSI_MINIPORT:
			{
				const auto query = static_cast< SRB_IO_CONTROL* >( irp_ptr->AssociatedIrp.SystemBuffer );

				if ( query->ControlCode == IOCTL_SCSI_MINIPORT_IDENTIFY )
					process_query( irp_ptr, stack_ptr, &process_smart_query );

				break;
			}
		default:break;
	}

	return original_dispatch_scsi( device_object, irp_ptr );
}

NTSTATUS driver_entry( )
{
	const auto kernel_module = search::for_module( _( "ntoskrnl.exe" ) );

	if ( !kernel_module )
		return STATUS_UNSUCCESSFUL;

	const auto IoDriverObjectType = reinterpret_cast< POBJECT_TYPE* >( search::for_export( kernel_module->image_base, _( "IoDriverObjectType" ) ) );
	const auto ObReferenceObjectByName = reinterpret_cast< NTSTATUS( __stdcall* )( PUNICODE_STRING, ULONG, PACCESS_STATE, ACCESS_MASK, POBJECT_TYPE, KPROCESSOR_MODE, PVOID, PVOID* ) >( search::for_export( kernel_module->image_base, _( "ObReferenceObjectByName" ) ) );

	PDRIVER_OBJECT disk_object = nullptr;
	if ( !NT_SUCCESS( ObReferenceObjectByName( &util::make_unicode( _( L"\\Driver\\Disk" ) ), OBJ_CASE_INSENSITIVE, nullptr, 0, *IoDriverObjectType, KernelMode, nullptr, reinterpret_cast< void** >( &disk_object ) ) ) )
		 return STATUS_UNSUCCESSFUL;

	const auto shell_code_location_disk = search::for_padding( disk_object );

	const auto shell_code_disk = make_shellcode
	(
		0x51ui8, 0x48ui8, 0xb9ui8, &driver_dispatch,
		0x48ui8, 0x87ui8, 0x0cui8, 0x24ui8, 0xc3ui8
	);

	util::write_kernel_memory( shell_code_location_disk, shell_code_disk.data( ), shell_code_disk.size( ) );

	original_dispatch = disk_object->MajorFunction[ 14u ];
	disk_object->MajorFunction[ 14u ] = reinterpret_cast< PDRIVER_DISPATCH >( shell_code_location_disk );

	ST_FN( ObfDereferenceObject )( disk_object );

	PDEVICE_OBJECT device_object = nullptr;
	PFILE_OBJECT file_object = nullptr;
	if ( !NT_SUCCESS( ST_FN( IoGetDeviceObjectPointer )( &util::make_unicode( _( L"\\Device\\ScsiPort0" ) ), 0, &file_object, &device_object ) ) )
		return STATUS_UNSUCCESSFUL;

	const auto scsi_object = device_object->DriverObject;

	const auto shell_code_location_scsi = search::for_padding( scsi_object );

	const auto shell_code_scsi = make_shellcode
	(
		0x51ui8, 0x48ui8, 0xb9ui8, &driver_dispatch_scsi,
		0x48ui8, 0x87ui8, 0x0cui8, 0x24ui8, 0xc3ui8
	);

	util::write_kernel_memory( shell_code_location_scsi, shell_code_scsi.data( ), shell_code_scsi.size( ) );

	original_dispatch_scsi = scsi_object->MajorFunction[ 14u ];
	scsi_object->MajorFunction[ 14u ] = reinterpret_cast< PDRIVER_DISPATCH >( shell_code_location_scsi );

	ST_FN( ObfDereferenceObject )( device_object );
	
	HANDLE directory_handle = nullptr;
	IO_STATUS_BLOCK directory_block{};
	OBJECT_ATTRIBUTES directory_attrs{};
	
	const auto windows_path = ST_FN( RtlGetNtSystemRoot )( );

	auto buffer = reinterpret_cast< wchar_t* >( smart::pool( ST_FN( ExAllocatePool )( PagedPool, 0x100 ) ).get( ) );
	wcscpy( buffer, windows_path );
	wcscat( buffer, _( L"\\System32\\restore" ) );

	InitializeObjectAttributes( &directory_attrs, &util::make_unicode( buffer ), OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, nullptr );
	ST_FN( ZwCreateFile )( &directory_handle, FILE_TRAVERSE, &directory_attrs, &directory_block, nullptr, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE, FILE_OPEN, FILE_DIRECTORY_FILE, nullptr, 0 );

	OBJECT_ATTRIBUTES file_attrs{};

	InitializeObjectAttributes( &file_attrs, &util::make_unicode( _( L"MachineGUID.txt" ) ), OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, directory_handle, nullptr );
	ST_FN( ZwDeleteFile )( &file_attrs );

	ST_FN( ZwClose )( directory_handle );

	spoof_registry( _( L"\\Registry\\Machine\\System\\CurrentControlSet\\Control\\SystemInformation" ), _( L"ComputerHardwareId" ), false );
	
	spoof_registry( _( L"\\Registry\\Hardware\\DeviceMap\\Scsi\\Scsi Port 0\\Target Id 0\\Logical Unit Id 0" ), _( L"SerialNumber" ), false );

	spoof_registry( _( L"\\Registry\\Software\\Microsoft\\Windows NT\\CurrentVersion" ), _( L"InstallDate" ), true );
	spoof_registry( _( L"\\Registry\\Software\\Microsoft\\Windows NT\\CurrentVersion" ), _( L"ProductId" ), false );

	spoof_registry( _( L"\\Registry\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows Activation Technologies\\AdminObject\\Store" ), _( L"MachineId" ), false );

	return STATUS_UNSUCCESSFUL;
}