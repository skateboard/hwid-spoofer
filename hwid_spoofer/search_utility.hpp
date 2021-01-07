#pragma once
#include <ntifs.h>
#include <cstdint>
#include <memory>
#include "xor_str.hpp"
#include "stealth_import.hpp"

namespace nt
{
	struct ldr_data_table_entry
	{
		LIST_ENTRY in_load_order_links;
		LIST_ENTRY in_memory_order_links;
		LIST_ENTRY in_initialization_order_links;
		void* dll_base;
		void* entry_point;
		std::uint32_t size_of_image;
		UNICODE_STRING full_dll_name;
		UNICODE_STRING base_dll_name;
	};

	enum system_info_class
	{
		SystemProcessInformation = 0x5,
		SystemModuleInformation = 0xb,
	};

	struct peb_ldr_data
	{
		char pad_0[ 0x10 ];
		LIST_ENTRY in_load_order_links;
	};

	struct peb64
	{
		char pad_0[ 0x18 ];
		peb_ldr_data* ldr;
	};

	struct rtl_process_info
	{
		HANDLE section;
		PVOID mapped_base;
		PVOID image_base;
		ULONG image_size;
		ULONG image_flags;
		USHORT load_order_idx;
		USHORT init_order_idx;
		USHORT load_count;
		USHORT file_name_offset;
		UCHAR full_path[ 256 ];
	};

	struct rtl_processes
	{
		ULONG count;
		rtl_process_info processes[ 1 ];
	};

	struct image_export_directory
	{
		std::uint32_t characteristics;
		std::uint32_t time_date_stamp;
		std::uint16_t major_version;
		std::uint16_t minor_version;
		std::uint32_t name;
		std::uint32_t base;
		std::uint32_t number_of_functions;
		std::uint32_t number_of_names;
		std::uint32_t address_of_functions;
		std::uint32_t address_of_names;
		std::uint32_t address_of_name_ordinals;
	};

	struct image_file_header
	{
		USHORT machine;
		USHORT number_of_sections;
		std::uint32_t time_date_stamp;
		std::uint32_t pointer_to_symbol_table;
		std::uint32_t number_of_symbols;
		USHORT size_of_optional_header;
		USHORT characteristics;
	};

	struct image_data_directory
	{
		std::uint32_t virtual_address;
		std::uint32_t size;
	};

	struct image_section_header
	{
		std::uint8_t  name[ 8 ];

		union
		{
			std::uint32_t physical_address;
			std::uint32_t virtual_size;
		} misc;

		std::uint32_t virtual_address;
		std::uint32_t size_of_raw_data;
		std::uint32_t pointer_to_raw_data;
		std::uint32_t pointer_to_relocations;
		std::uint32_t pointer_to_line_numbers;
		std::uint16_t number_of_relocations;
		std::uint16_t number_of_line_numbers;
		std::uint32_t characteristics;
	};

	struct image_optional_header
	{
		std::uint16_t magic;
		std::uint8_t major_linker_version;
		std::uint8_t minor_linker_version;
		std::uint32_t size_of_code;
		std::uint32_t size_of_initialized_data;
		std::uint32_t size_of_uninitialized_data;
		std::uint32_t address_of_entry_point;
		std::uint32_t base_of_code;
		std::uint64_t image_base;
		std::uint32_t section_alignment;
		std::uint32_t file_alignment;
		std::uint16_t major_operating_system_version;
		std::uint16_t minor_operating_system_version;
		std::uint16_t major_image_version;
		std::uint16_t minor_image_version;
		std::uint16_t major_subsystem_version;
		std::uint16_t minor_subsystem_version;
		std::uint32_t win32_version_value;
		std::uint32_t size_of_image;
		std::uint32_t size_of_headers;
		std::uint32_t check_sum;
		std::uint16_t subsystem;
		std::uint16_t dll_characteristics;
		std::uint64_t size_of_stack_reserve;
		std::uint64_t size_of_stack_commit;
		std::uint64_t size_of_heap_reserve;
		std::uint64_t size_of_heap_commit;
		std::uint32_t loader_flags;
		std::uint32_t number_of_rva_and_sizes;
		image_data_directory data_directory[ 16 ];
	};

	struct image_nt_headers
	{
		std::uint32_t signature;
		image_file_header file_header;
		image_optional_header optional_header;
	};

	struct image_dos_header
	{
		std::uint16_t e_magic;
		std::uint16_t e_cblp;
		std::uint16_t e_cp;
		std::uint16_t e_crlc;
		std::uint16_t e_cparhdr;
		std::uint16_t e_minalloc;
		std::uint16_t e_maxalloc;
		std::uint16_t e_ss;
		std::uint16_t e_sp;
		std::uint16_t e_csum;
		std::uint16_t e_ip;
		std::uint16_t e_cs;
		std::uint16_t e_lfarlc;
		std::uint16_t e_ovno;
		std::uint16_t e_res[ 4 ];
		std::uint16_t e_oemid;
		std::uint16_t e_oeminfo;
		std::uint16_t e_res2[ 10 ];
		std::int32_t e_lfanew;
	};

	inline auto image_first_section( image_nt_headers* nt_header ) noexcept
	{
		return reinterpret_cast< image_section_header* >
			(
				reinterpret_cast< std::uint64_t >( nt_header ) +
				FIELD_OFFSET( image_nt_headers, optional_header ) +
				nt_header->file_header.size_of_optional_header
				);
	}
}

namespace smart
{
	struct unique_pool
	{
		void operator( )( void* pool ) noexcept
		{
			if ( pool )
				ST_FN( ExFreePoolWithTag )( pool, 0 );
		}
	};

	struct unique_dereference
	{
		void operator( )( void* object ) noexcept
		{
			if ( object )
				ST_FN( ObfDereferenceObject )( object );
		}
	};

	struct unique_handle
	{
		void operator( )( void* object ) noexcept
		{
			if ( object )
				ST_FN( ZwClose )( object );
		}
	};

	template <typename T>
	using object = std::unique_ptr<std::remove_pointer_t<T>, unique_dereference>;
	using pool = std::unique_ptr<void, unique_pool>;
	using handle = std::unique_ptr<void, unique_handle>;
}

namespace search
{
	inline nt::image_nt_headers* for_file_header( const void* module_address )
	{
		const auto module_base = reinterpret_cast< std::uint64_t >( module_address );

		if ( !module_base )
			return nullptr;

		const auto dos_header = reinterpret_cast< nt::image_dos_header* >( module_base );

		if ( !dos_header )
			return nullptr;

		return reinterpret_cast< nt::image_nt_headers* >( module_base + dos_header->e_lfanew );
	}

	inline void* for_export( const void* module_address, const char* export_name )
	{
		const auto nt_header = search::for_file_header( module_address );

		if ( !nt_header )
			return nullptr;

		const auto image_base = nt_header->optional_header.image_base;

		if ( !image_base )
			return nullptr;

		const auto export_directory = reinterpret_cast< const nt::image_export_directory* >( image_base + nt_header->optional_header.data_directory[ 0 ].virtual_address );
		const auto export_functions = reinterpret_cast< const std::uint32_t* >( image_base + export_directory->address_of_functions );
		const auto export_ordinals = reinterpret_cast< const std::uint16_t* >( image_base + export_directory->address_of_name_ordinals );
		const auto export_names = reinterpret_cast< const std::uint32_t* >( image_base + export_directory->address_of_names );

		for ( auto i = 0u; i < export_directory->number_of_names; i++ )
		{
			if ( strcmp( reinterpret_cast< const char* >( image_base + export_names[ i ] ), export_name ) != 0 )
				continue;

			return reinterpret_cast< void* >( image_base + export_functions[ export_ordinals[ i ] ] );
		}

		return nullptr;
	}


	nt::rtl_process_info* for_module( const char* module_name )
	{
		static const auto ntoskrnl_module = *reinterpret_cast< void** >( uint64_t( PsLoadedModuleList ) + 0x30 );
		static const auto ZwQuerySystemInformation = reinterpret_cast< NTSTATUS( __stdcall* )( nt::system_info_class, PVOID, ULONG, PULONG ) >( for_export( ntoskrnl_module, _( "ZwQuerySystemInformation" ) ) );

		auto needed_bytes = 8192ul;
		smart::pool buffer_pool( ST_FN( ExAllocatePoolWithTag )( PagedPool, needed_bytes, 'udoM' ) );

		if ( !buffer_pool.get( ) )
			return nullptr;

		auto current_status = ZwQuerySystemInformation( nt::SystemModuleInformation, buffer_pool.get( ), needed_bytes, &needed_bytes );

		while ( current_status == STATUS_INFO_LENGTH_MISMATCH )
		{
			buffer_pool.reset( ST_FN( ExAllocatePoolWithTag )( PagedPool, needed_bytes, 'udoM' ) );

			if ( !buffer_pool )
				return nullptr;

			current_status = ZwQuerySystemInformation( nt::SystemModuleInformation, buffer_pool.get( ), needed_bytes, &needed_bytes );
		}

		if ( !NT_SUCCESS( current_status ) )
			return nullptr;

		const auto current_processes = static_cast< nt::rtl_processes* >( buffer_pool.get( ) );

		if ( !current_processes )
			return nullptr;

		for ( auto i = 0u; i < current_processes->count; i++ )
		{
			const auto current_process = &current_processes->processes[ i ];

			if ( !current_process )
				continue;

			const auto file_name = reinterpret_cast< const char* >( current_process->file_name_offset + current_process->full_path );

			if ( std::strcmp( file_name, module_name ) != 0 )
				continue;

			return current_process;
		}

		return nullptr;
	}

	std::uint8_t* for_signature( const nt::rtl_process_info* module, const char* signature, const char* signature_mask )
	{
		if ( !module )
			return nullptr;

		const auto module_start = reinterpret_cast< std::uint8_t* >( module->image_base );
		const auto module_size = module_start + module->image_size;

		/* iterate the entire module */
		for ( auto segment = module_start; segment < module_size; segment++ )
		{
			if ( [ & ]( const std::uint8_t* bytes ) -> bool
				 {
					 auto sig_as_bytes = reinterpret_cast< std::uint8_t* >( const_cast< char* >( signature ) );

						 /* iterate through validity of the mask, mask is essentially equal to the byte sequence specific in signature */
						 for ( ; *signature_mask; ++signature_mask, ++bytes, ++sig_as_bytes )
						 {
							 /* if the signature misk is 'x' ( a valid byte, not an always match / wildcard ), and the current byte is not equal to the byte in the sig, then break */
							 if ( *signature_mask == 'x' && *bytes != *sig_as_bytes )
								 return false;
						 }

					 return ( *signature_mask ) == 0;
				 }( segment )
					 )
				return segment;
		}

		return nullptr;
	}

	std::uint8_t* for_padding( const PDRIVER_OBJECT driver_object, const std::size_t len = 16u )
	{
		const auto nt_header = search::for_file_header( driver_object->DriverStart );
		const auto first_section = nt::image_first_section( nt_header );

		nt::image_section_header* text_section = nullptr;

		for ( auto section = first_section; section < first_section + nt_header->file_header.number_of_sections; section++ )
		{
			if ( !section )
				continue;

			if ( std::strcmp( reinterpret_cast< const char* >( section->name ), _( ".text" ) ) )
				continue;

			text_section = section;
			break;
		}

		if ( !text_section )
			return nullptr;

		const auto section_start = reinterpret_cast< std::uint8_t* >( driver_object->DriverStart ) + text_section->virtual_address;
		const auto section_end = section_start + text_section->misc.virtual_size;

		for ( auto current_byte = section_start + len; current_byte < section_end - len; current_byte++ )
		{
			static auto pad_counter = 0;

			if ( *current_byte == 0xcc )
				pad_counter++;
			else
				pad_counter = 0;

			if ( pad_counter >= len )
				return ( current_byte - len ) + 1;
		}

		return nullptr;
	}
}