#pragma once
#include <windows.h>
#include <string>
#include <cstdint>

namespace pe
{
	class pe
	{
	public:
		using pre_callback_t = bool( * )( std::string module_name );
		using post_callback_t = 
			bool( * )( 
				std::string module_name,
				void* func_addr,
				std::string func_name );

		void* image_base;
		std::size_t image_size;
		PIMAGE_DOS_HEADER pdos_header;
		PIMAGE_NT_HEADERS pnt_headers;

		pe( void* image_buffer );
		~pe();

		bool relocate_image( uint64_t delta ) const noexcept;
		bool resolve_imports( 
			pre_callback_t pre_callback, 
			post_callback_t post_callback, 
			bool ret_on_pre_fail, 
			bool ret_on_post_fail ) const noexcept;

		bool is_dos_header_valid() const noexcept;
		bool is_nt_headers_valid() const noexcept;
		bool is_64bit_image() const noexcept;
	private:
	};
} // namespace pe