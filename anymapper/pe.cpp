#include "pe.hpp"

pe::pe::pe( void* image_buffer )
{
	image_base = image_buffer;

	pdos_header = ( PIMAGE_DOS_HEADER )image_buffer;

	if ( !is_dos_header_valid() )
		return;

	pnt_headers = ( PIMAGE_NT_HEADERS )
		( ( uint64_t )image_buffer + pdos_header->e_lfanew );

	if ( !is_nt_headers_valid() )
		return;

	image_size = pnt_headers->OptionalHeader.SizeOfImage;
}

pe::pe::~pe()
{
}

bool pe::pe::fix_sections( void* raw )
{
	const PIMAGE_SECTION_HEADER section = 
		IMAGE_FIRST_SECTION( this->pnt_headers );

	for ( 
		auto i = 0; 
		i < this->pnt_headers->FileHeader.NumberOfSections; 
		i++ )
	{
		//section->PointerToRawData = section->VirtualAddress;
		//section->SizeOfRawData = section->Misc.VirtualSize;

		memcpy(
			( void* )( ( uint64_t )image_base + section[ i ].VirtualAddress ),
			( void* )( ( uint64_t )raw + section[ i ].PointerToRawData ),
			section[ i ].SizeOfRawData );
	}

	return true;
}

bool pe::pe::relocate_image( uint64_t delta ) const noexcept
{
	if ( !delta )
		return false;

	if ( !pnt_headers )
		return false;

	const auto relocation_data =
		pnt_headers->OptionalHeader
		.DataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC ];

	if ( !relocation_data.Size || !relocation_data.VirtualAddress )
		return false;

	PIMAGE_BASE_RELOCATION relocation_entry =
		reinterpret_cast< PIMAGE_BASE_RELOCATION >( 
			( uint64_t )image_base + relocation_data.VirtualAddress );

	__try
	{
		volatile auto ptr_valid = relocation_entry->VirtualAddress;
	}
	__except ( 1 )
	{
		return false;
	}

	const auto relocation_range = 
		( uint64_t )( ( uint64_t )relocation_entry + relocation_data.Size );

	if ( IsBadReadPtr( relocation_entry, sizeof( uint64_t ) ) == TRUE )
		return false;

	while (
		IsBadReadPtr( relocation_entry, sizeof( uint64_t ) ) == FALSE && 
		relocation_entry->VirtualAddress &&
		relocation_entry->VirtualAddress < relocation_range &&
		relocation_entry->SizeOfBlock )
	{
		const auto ibr_size = sizeof( IMAGE_BASE_RELOCATION );

		const auto address = ( uint64_t )( ( uint64_t )this->image_base + relocation_entry->VirtualAddress );
		const auto count = ( relocation_entry->SizeOfBlock - ibr_size ) / sizeof( uint16_t );
		const auto list = reinterpret_cast< uint16_t* >( ( uint64_t )relocation_entry + ibr_size );

		static_assert( sizeof( uint16_t ) == 2, "must be 2, this is due to non-64bit" );

		for ( auto i = 0; i < count; i++ )
		{
			const uint16_t type = list[ i ] >> 12;
			const uint16_t offset = list[ i ] & 0xFFF;

			if ( type == IMAGE_REL_BASED_DIR64 )
			{
				*( uint64_t* )( address + offset ) += delta;
			}
		}

		relocation_entry = 
			reinterpret_cast< PIMAGE_BASE_RELOCATION >( 
				( uint64_t )relocation_entry + relocation_entry->SizeOfBlock );
	}

	return true;
}

bool pe::pe::resolve_imports( 
	pre_callback_t pre_callback,
	post_callback_t post_callback,
	bool ret_on_pre_fail,
	bool ret_on_post_fail ) const noexcept
{
	if ( !pnt_headers )
		return false;

	const auto import_data =
		pnt_headers->OptionalHeader
		.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ];

	if ( !import_data.Size )
		return false;

	const auto base_import = import_data.VirtualAddress;

	if ( !base_import )
		return false;

	auto import_entry = 
		reinterpret_cast< PIMAGE_IMPORT_DESCRIPTOR >( 
			( uint64_t )pdos_header + base_import );

	while ( import_entry->FirstThunk )
	{
		const auto module_name =
			std::string(
				reinterpret_cast< char* >(
					( uint64_t )pdos_header + import_entry->Name ) );

		if ( pre_callback )
		{
			const bool result = pre_callback( module_name );

			if ( !result && ret_on_pre_fail )
				return result;
		}

		auto first_thunk =
			reinterpret_cast< PIMAGE_THUNK_DATA64 >(
				( uint64_t )pdos_header + import_entry->FirstThunk );

		auto first_thunk_original =
			reinterpret_cast< PIMAGE_THUNK_DATA64 >(
				( uint64_t )pdos_header + import_entry->OriginalFirstThunk );

		while ( first_thunk_original->u1.Function )
		{
			auto thunk_data =
				reinterpret_cast< PIMAGE_IMPORT_BY_NAME >(
					( uint64_t )pdos_header + first_thunk_original->u1.AddressOfData );

			if ( post_callback )
			{
				const bool result = post_callback(
					module_name,
					&first_thunk_original->u1.Function,
					thunk_data->Name );

				if ( !result && ret_on_post_fail )
					return result;
			}

			first_thunk++;
			first_thunk_original++;
		}

		import_entry++;
	}

	return true;
}

bool pe::pe::is_dos_header_valid() const noexcept
{
	if ( !pdos_header )
		return false;

	return pdos_header->e_magic == IMAGE_DOS_SIGNATURE;
}

bool pe::pe::is_nt_headers_valid() const noexcept
{
	if ( !pnt_headers )
		return false;

	return pnt_headers->Signature == IMAGE_NT_SIGNATURE;
}

bool pe::pe::is_64bit_image() const noexcept
{
	return pnt_headers->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
}

bool pe::pe::valid_ptr( void* ptr ) const
{
	// TODO: implement
	return true;
}
