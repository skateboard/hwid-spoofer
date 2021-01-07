#pragma once
#include "stealth_import.hpp"
#include "serial_generator.hpp"
#include "general_utility.hpp"

void spoof_registry( const wchar_t* key, const wchar_t* value, const bool integer = true )
{
	HANDLE raw_registry_handle = nullptr;
	OBJECT_ATTRIBUTES object_attrs;

	InitializeObjectAttributes( &object_attrs, &util::make_unicode( key ), OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, nullptr );
	if ( !NT_SUCCESS( ST_FN( ZwOpenKey )( &raw_registry_handle, KEY_WRITE, &object_attrs ) ) )
		return;

	if ( integer )
	{
		auto random_seed = static_cast< uint32_t >( __rdtsc( ) );

		ST_FN( ZwSetValueKey )( raw_registry_handle, &util::make_unicode( value ), 0, REG_DWORD, &random_seed, 4 );
	}
	else
	{
		auto new_array = reinterpret_cast< wchar_t* >( smart::pool( ST_FN( ExAllocatePool )( PagedPool, 35 ) ).get( ) );
		memset( new_array, 0, 17 * 2 );
		spoof_serial( new_array );
		auto unicode_str = util::make_unicode( new_array );

		ST_FN( ZwSetValueKey )( raw_registry_handle, &util::make_unicode( value ), 0, REG_SZ, unicode_str.Buffer, unicode_str.Length + 2 );
	}

	//ST_FN( ZwFlushKey )( raw_registry_handle );
	ST_FN( ZwClose )( raw_registry_handle );
}