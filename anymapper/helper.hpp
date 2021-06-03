#pragma once
#include <windows.h>
#include <string>

namespace helper
{
	//
	// https://stackoverflow.com/questions/215963/how-do-you-properly-use-widechartomultibyte/3999597#3999597
	//
	std::wstring s2ws( const std::string& str )
	{
		std::wstring wstrTo;
		wchar_t* wszTo = new wchar_t[ str.length() + 1 ];
		wszTo[ str.size() ] = L'\0';
		MultiByteToWideChar( CP_ACP, 0, str.c_str(), -1, wszTo, ( int )str.length() );
		wstrTo = wszTo;
		delete[] wszTo;
		return wstrTo;
	}
} // namespace helper