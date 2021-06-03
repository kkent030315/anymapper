/*

	MIT License

	Copyright (c) 2021 Kento Oki

	Permission is hereby granted, free of charge, to any person obtaining a copy
	of this software and associated documentation files (the "Software"), to deal
	in the Software without restriction, including without limitation the rights
	to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
	copies of the Software, and to permit persons to whom the Software is
	furnished to do so, subject to the following conditions:

	The above copyright notice and this permission notice shall be included in all
	copies or substantial portions of the Software.

	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
	SOFTWARE.

*/

#pragma once
#include <windows.h>
#include <string_view>
#include <filesystem>

#include "nt.hpp"
#include "pe.hpp"
#include "kernel.hpp"
#include "filebuf.hpp"
#include "helper.hpp"
#include "../anycall/libanycall/libanycall.h"

#define ANYMAPPER_POOL_TAG 'myna'

namespace anymapper
{
	bool inject_driver( 
		const std::wstring_view driver_path )
	{
		if ( !std::filesystem::exists( driver_path ) )
		{
			printf( "[!] %ls does not exists\n", driver_path.data() );
			return false;
		}

		printf( "[~] loading: %ls\n", driver_path.data() );

		/*void* buffer = reinterpret_cast< uint8_t* >(
			LoadLibraryEx( 
				driver_path.data(),
				0,
				DONT_RESOLVE_DLL_REFERENCES ) );*/

		std::vector<uint8_t> file_buffer;
		
		if ( !filebuf::copy_file_to_buffer( driver_path, file_buffer ) )
		{
			printf( "[!] failed to prepare buffer\n" );
			return false;
		}

		if ( !file_buffer.size() )
		{
			printf( "[!] failed to load driver to our buffer\n" );
			return false;
		}

		void* buffer = VirtualAlloc(
			NULL,
			pe::pe( file_buffer.data() ).pnt_headers->OptionalHeader.SizeOfImage,
			MEM_RESERVE | MEM_COMMIT,
			PAGE_READWRITE );

		if ( !buffer )
		{
			printf( "[!] failed to allocate user buffer (0x%lX)\n", GetLastError() );
			return false;
		}

		printf( "[+] user buffer allocated @ 0x%p\n", buffer );

		memcpy( buffer, &file_buffer.data()[ 0 ], file_buffer.size() );

		printf( "[+] image mapped to 0x%p\n", buffer );

		const auto PE = new pe::pe( buffer );

		if ( !PE->is_dos_header_valid() )
		{
			printf( "[!] \033[0;101;30minvalid dos signature: 0x%lX\033[0m\n", 
				PE->pdos_header->e_magic );
			//FreeLibrary( ( HMODULE )buffer );
			return false;
		}

		if ( !PE->is_nt_headers_valid() )
		{
			printf( "[!] \033[0;101;30minvalid nt headers signature: 0x%lX\033[0m\n", 
				PE->pnt_headers->Signature );
			//FreeLibrary( ( HMODULE )buffer );
			return false;
		}

		if ( !PE->is_64bit_image() )
		{
			printf( "[!] \033[0;101;30mimage type must be 64-bit: 0x%lX\033[0m\n",
				PE->pnt_headers->OptionalHeader.Magic );
			//FreeLibrary( ( HMODULE )buffer );
			return false;
		}

		printf( "[~] image: 0x%llX -> 0x%llX\n", 
			( uint64_t )buffer, ( uint64_t )buffer + PE->image_size );
		printf( "[~] image size: 0x%llX\n", PE->image_size );

		const std::size_t section_size = 
			IMAGE_FIRST_SECTION( PE->pnt_headers )->VirtualAddress;

		const std::size_t size_to_alloc = 
			PE->image_size - section_size;

		printf( "[+] allocating kernel buffer with size of 0x%llX\n", size_to_alloc );

		void* kbuffer = ANYCALL_INVOKE( 
			ExAllocatePoolWithTag, 
			NonPagedPool, size_to_alloc, ANYMAPPER_POOL_TAG );

		if ( !kbuffer )
		{
			printf( "[!] \033[0;101;30mfailed to allocate kernel buffer\033[0m\n" );
			//FreeLibrary( ( HMODULE )buffer );
			return false;
		}

		printf( "[+] kernel buffer allocated @ 0x%p\n", kbuffer );

		const auto delta = 
			( uint64_t )kbuffer - PE->pnt_headers->OptionalHeader.ImageBase - section_size;

		//memcpy( buffer, file_buffer.data(), PE->pnt_headers->OptionalHeader.SizeOfHeaders );

		printf( "[+] fixing sections...\n" );

		if ( !PE->fix_sections( file_buffer.data() ) )
		{
			printf( "[!] \033[0;101;30mfailed to fix image sections\033[0m\n" );
			//FreeLibrary( ( HMODULE )buffer );
			ANYCALL_INVOKE( ExFreePool, kbuffer );
			return false;
		}

		printf( "[+] relocating image with delta 0x%llX...\n", delta );

		if ( !PE->relocate_image( delta ) )
		{
			printf( "[!] \033[0;101;30mfailed to relocate image\033[0m\n" );
			//FreeLibrary( ( HMODULE )buffer );
			ANYCALL_INVOKE( ExFreePool, kbuffer );
			return false;
		}

		const pe::pe::pre_callback_t pre_callback = []( 
			std::string_view module_name ) -> bool
		{
			if ( module_name.empty() )
				return false;

			printf( "[~] -> import module: %s\n", module_name.data() );

			return !!libanycall::find_sysmodule( module_name ).base_address;
		};

		const pe::pe::post_callback_t post_callback = []( 
			std::string_view module_name,
			void* func_addr, std::string_view func_name ) -> bool
		{
			if ( module_name.empty() || func_name.empty() )
				return false;

			printf( "[~] --> import function: %s @ ", func_name.data() );

			/*const auto routine_address = module_name == "ntoskrnl.exe" ?
				libanycall::find_ntoskrnl_export( func_name ) :
				libanycall::find_export( module_name, func_name );*/
			const auto routine_address = module_name == "ntoskrnl.exe" ?
				kernel::find_routine_address( helper::s2ws( func_name.data() ) ) : 0;

			printf( "0x%llX\n", routine_address );

			if ( !routine_address )
				return false;

			*reinterpret_cast< uint64_t* >( func_addr ) = routine_address;

			return true;
		};

		printf( "[+] resolving imports...\n" );

		if ( !PE->resolve_imports( pre_callback, post_callback, true, true ) )
		{
			printf( "[!] \033[0;101;30mfailed to resolve imports\033[0m\n" );
			//FreeLibrary( ( HMODULE )buffer );
			ANYCALL_INVOKE( ExFreePool, kbuffer );
			return false;
		}

		printf( "[+] copying payload to the kernel buffer...\n" );

		kernel::memcpy( 
			kbuffer, 
			( void* )( ( uint64_t )buffer + section_size ),
			size_to_alloc );

		printf( "[+] payload sent to 0x%p\n", kbuffer );

		//printf( "stop\n" ); return false;

		const auto entry_point_rva = 
			PE->pnt_headers->OptionalHeader.AddressOfEntryPoint;

		const auto entry_point_addr = 
			( uint64_t )kbuffer +
			( uint64_t )entry_point_rva - section_size;

		printf( "[+] entry point rva: 0x%lX\n", entry_point_rva );
		printf( "[+] entry point @ 0x%llX\n", entry_point_addr );

		uint8_t readed[ 8 ] = { 0 };
		memcpy( &readed[ 0 ], &file_buffer.data()[ 0 ], sizeof( readed ) );
		printf( "readed: %02X %02X %02X %02X %02X %02X %02X %02X\n",
			readed[ 0 ], readed[ 1 ], readed[ 2 ], readed[ 3 ],
			readed[ 4 ], readed[ 5 ], readed[ 6 ], readed[ 7 ] );

		kernel::memcpy( &readed[ 0 ], ( void* )entry_point_addr, sizeof( readed ) );
		printf( "readed: %02X %02X %02X %02X %02X %02X %02X %02X\n",
			readed[ 0 ], readed[ 1 ], readed[ 2 ], readed[ 3 ],
			readed[ 4 ], readed[ 5 ], readed[ 6 ], readed[ 7 ] );

		//printf( "stop\n" ); return false;
		uint8_t shell[] = { 0x48, 0xc7, 0xc0, 0x05, 0x00, 0x00, 0x0C, 0xc3 };
		kernel::memcpy( ( void* )entry_point_addr, &shell, sizeof( shell ) );

		const NTSTATUS nt_status =
			libanycall::invoke< DriverEntry >(
				( void* )entry_point_addr, ( PVOID )0, ( PVOID )0 );

		printf( "[+] DriverEntry returned 0x%lX\n", nt_status );

		printf( "[+] done!\n" );
		//FreeLibrary( ( HMODULE )buffer );
		ANYCALL_INVOKE( ExFreePool, kbuffer );
		return true;
	}
} // namespace anymapper