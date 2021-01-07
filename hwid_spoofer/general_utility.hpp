#pragma once
#include <ntifs.h>
#include <string>
#include "stealth_import.hpp"

namespace util
{
	UNICODE_STRING make_unicode( const wchar_t* str )
	{
		UNICODE_STRING string{};
		
		string.Buffer = const_cast< wchar_t* >( str );

		auto str_len = std::wcslen( str ) * 2u;

		if ( str_len >= 0xfffe )
			str_len = 0xfffc;

		string.Length = str_len;
		string.MaximumLength = str_len + 2u;

		return string;
	}

	void write_kernel_memory( void* dst, const void* src, const std::size_t size )
	{
		const std::unique_ptr<MDL, decltype( &IoFreeMdl )> mdl( ST_FN( IoAllocateMdl )( dst, size, FALSE, FALSE, nullptr ), &IoFreeMdl );

		if ( !mdl )
			return;

		ST_FN( MmProbeAndLockPages )( mdl.get( ), KernelMode, IoReadAccess );

		const auto mapped_page = ST_FN( MmMapLockedPagesSpecifyCache )( mdl.get( ), KernelMode, MmNonCached, nullptr, FALSE, NormalPagePriority );

		if ( !mapped_page )
			return;

		if ( !NT_SUCCESS( ST_FN( MmProtectMdlSystemAddress )( mdl.get( ), PAGE_EXECUTE_READWRITE ) ) )
			return;

		std::memcpy( mapped_page, src, size );

		ST_FN( MmUnmapLockedPages )( mapped_page, mdl.get( ) );
		ST_FN( MmUnlockPages )( mdl.get( ) );
	}
}