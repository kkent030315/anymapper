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

#include "../anycall/libanycall/libanycall.h"

#pragma comment( lib, "ntdll.lib" ) // RtlInitUnicodeString

namespace kernel
{
	//
	// this pointer holds ntoskrnl's exported memcpy
	// not rva, absolute address
	//
	inline void* ntoskrnl_memcpy = {};

	//
	// memcpy of kernel virtual memory
	// invoke memcpy inside ntoskrnl
	//
	void memcpy( void* dst, void* src, size_t size )
	{
		if ( !ntoskrnl_memcpy )
			ntoskrnl_memcpy = ( void* )
			libanycall::find_ntoskrnl_export( "memcpy" );

		libanycall::invoke<decltype( &memcpy )>
			( ntoskrnl_memcpy, dst, src, size );
	}

	//
	// find system routine by MmGetSystemRoutineAddress
	//
	uint64_t find_routine_address( const std::wstring_view routine_name )
	{
		UNICODE_STRING routine_name_us;
		RtlInitUnicodeString( &routine_name_us, routine_name.data() );
		return ( uint64_t )ANYCALL_INVOKE( MmGetSystemRoutineAddress, &routine_name_us );
	}
}