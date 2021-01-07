#pragma once
#include "search_utility.hpp"

#define tolower(c) (c >= 'A' && c <= 'Z' ? (c | (1 << 5)) : c)
#define tolower_w(c) (c >= L'A' && c <= L'Z' ? (c | (1 << 5)) : c)

struct hasher_t
{
	using value_t = std::uint64_t;

	constexpr static value_t         offset = 0x811c9dc5u;
	constexpr static value_t         prime = 0x1000193u;
	constexpr static std::uint64_t   prime64 = prime;

	__forceinline constexpr static value_t single( value_t val, char character ) noexcept
	{
		return static_cast< value_t >(
			( val ^ tolower( character ) ) * prime64
			);
	}

	__forceinline constexpr static value_t single_w( value_t val, wchar_t character ) noexcept
	{
		return static_cast< value_t >(
			( val ^ character ) * prime64
			);
	}
};

template <class char_t = char>
__forceinline constexpr hasher_t::value_t
hashk( const char_t* str, hasher_t::value_t val = hasher_t::offset ) noexcept
{
	return ( *str ? hashk( str + 1u, hasher_t::single( val, *str ) ) : val );
}

template <class char_t = char>
__forceinline constexpr hasher_t::value_t
hash( const char_t* str ) noexcept
{
	hasher_t::value_t val = hasher_t::offset;

	for ( ; ; )
	{
		char character = *str++;

		if ( !character )
			return val;

		val = hasher_t::single( val, character );
	}
}

extern "C" NTSYSAPI PLIST_ENTRY PsLoadedModuleList;

template <std::size_t Hash, typename T>
struct stealth_import
{
	__forceinline T get( ) noexcept
	{
		static const auto module_image = *reinterpret_cast< void** >( uint64_t( PsLoadedModuleList ) + 0x30 );
		static const auto nt_header = search::for_file_header( module_image );

		static  auto image_base = nt_header->optional_header.image_base;

		if ( !image_base )
			return nullptr;

		static const auto export_directory = reinterpret_cast< const nt::image_export_directory* >( image_base + nt_header->optional_header.data_directory[ 0 ].virtual_address );
		static const auto export_functions = reinterpret_cast< const std::uint32_t* >( image_base + export_directory->address_of_functions );
		static const auto export_ordinals = reinterpret_cast< const std::uint16_t* >( image_base + export_directory->address_of_name_ordinals );
		static const auto export_names = reinterpret_cast< const std::uint32_t* >( image_base + export_directory->address_of_names );

		for ( auto i = 0u; i < export_directory->number_of_names; i++ )
		{
			const auto export_hash = hash( reinterpret_cast< const char* >( image_base + export_names[ i ] ) );

			if ( export_hash != Hash )
				continue;

			return ( T )( reinterpret_cast< void* >( image_base + export_functions[ export_ordinals[ i ] ] ) );
		}

		return {};
	}

	template <class... Args>
	__forceinline decltype( auto ) operator( )( Args&& ... args ) noexcept
	{
		return get( )( std::forward< Args >( args )... );
	}
};

#define ST_FN(name) stealth_import<hashk(#name), decltype(&name)>{}