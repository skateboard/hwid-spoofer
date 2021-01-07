#pragma once
#include <cstdint>
#include <intrin.h>
#include "stealth_import.hpp"

static __forceinline bool is_pronouncable( char c )
{
	return ( c >= '0' && c <= '9' )
		|| ( c >= 'A' && c <= 'Z' )
		|| ( c >= 'a' && c <= 'z' );
}

static __forceinline bool is_pronouncable( wchar_t c )
{
	return ( c >= L'0' && c <= L'9' )
		|| ( c >= L'A' && c <= L'Z' )
		|| ( c >= L'a' && c <= L'z' );
}

static __forceinline char to_digit( char c )
{
	return c - '0';
}

static __forceinline char to_lower( char c )
{
	return ( c >= 'A' && c <= 'Z' ) ? c | ( 1 << 5 ) : c;
}

void spoof_serial( char* str )
{						
	static const auto unique_offset  = __rdtsc( );
	constexpr auto alphabet          = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
	constexpr auto alphabet_len      = 36u;

	for ( auto i = 0u; i < std::strlen( str ); i++ )
	{
		if ( !is_pronouncable( str[ i ] ) )
			continue;
		
		str[ i ] = alphabet[ ( hasher_t::single( hasher_t::offset, str[ i ] ) + unique_offset ) % alphabet_len ];
	}
}

void spoof_serial( wchar_t* str )
{
	static const auto unique_offset = __rdtsc( );
	constexpr auto alphabet = L"ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
	constexpr auto alphabet_len = 36u;

	for ( auto i = 0u; i < std::wcslen( str ); i++ )
	{
		if ( !is_pronouncable( str[ i ] ) )
			continue;

		str[ i ] = alphabet[ ( hasher_t::single_w( hasher_t::offset, str[ i ] ) + unique_offset ) % alphabet_len ];
	}
}