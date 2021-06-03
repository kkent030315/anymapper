#pragma once
#include <windows.h>
#include <filesystem>
#include <fstream>

namespace filebuf
{
	bool copy_file_to_buffer( const std::wstring_view file_path, std::vector< uint8_t >& buffer )
	{
		if ( !std::filesystem::exists( file_path ) )
			return false;

		std::ifstream fstream( file_path, std::ios::binary );

		if ( !fstream )
			return false;

		buffer.assign( 
			std::istreambuf_iterator<char>( fstream ), 
			std::istreambuf_iterator<char>() );
		
		fstream.close();
		return true;
	}
} // namespace filebuf