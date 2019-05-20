#pragma once

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32) && !defined(__CYGWIN__)
#include <Windows.h>
#endif

#include <cstdint>
#include <memory>

namespace vtable_hook
{
	namespace mem
	{
		/// <summary>
		/// Will get the length of a given vtable
		/// </summary>
		/// <param name="table">Pointer of which the vtable will be retrieved and searched</param>
		/// <returns>Amount of virtual functions found</returns>
		uint32_t get_vtable_length( uintptr_t* table )
		{
			auto length = uint32_t{};

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32) && !defined(__CYGWIN__)
			for ( length = 0; table[ length ]; length++ )
				if ( IS_INTRESOURCE( table[ length ] ) )
					break;
#else
			/// TODO: Needs a better way
			for ( length = 0; table[ length ]; length++ )
				if ( !table[ length ] )
					break;
#endif
			return length;
		}
	}

	struct mem_protect_t
	{
		/// <summary>
		/// Creates a protection object with the given arguments
		/// </summary>
		/// <param name="address">The address which should be affected</param>
		/// <param name="size">The size of the memory which should be affected</param>
		/// <param name="flags">The new flags of the memory</param>
		mem_protect_t( LPVOID address, uint32_t size, DWORD flags ) : m_address( address ), m_size( size ), m_flags( 0 )
		{
			VirtualProtect( m_address, m_size, flags, &m_flags );
		}

		/// <summary>
		/// Destroys the protection object and automatically restores old flags
		/// </summary>
		~mem_protect_t()
		{
			VirtualProtect( m_address, m_size, m_flags, &m_flags );
		}

		/// <summary>
		/// Address of affected memory
		/// </summary>
		LPVOID m_address;

		/// <summary>
		/// Size of affected memory
		/// </summary>
		uint32_t m_size;

		/// <summary>
		/// Old proctection flags
		/// </summary>
		DWORD m_flags;
	};

#define INIT_MEM_PROTECT_RW( address, size ) auto protect = mem_protect_t( address, size, PAGE_READWRITE );

	struct hook_t
	{
		/// <summary>
		/// Creates default hook object
		/// </summary>
		hook_t() = default;

		/// <summary>
		/// Sets up a hook with given object pointer
		/// </summary>
		/// <param name="ptr">Address of object from desired vtable</param>
		hook_t( uintptr_t ptr ) : m_vtable( reinterpret_cast< uintptr_t** >( ptr ) ), m_table_length( 0 ), m_orig( nullptr ), m_replace( nullptr ) {};

		/// <summary>
		/// Sets up a hook with given object pointer
		/// </summary>
		/// <param name="ptr">Address of object from desired vtable</param>
		hook_t( void* ptr ) : m_vtable( reinterpret_cast< uintptr_t** >( ptr ) ), m_table_length( 0 ), m_orig( nullptr ), m_replace( nullptr ) {};

		/// <summary>
		/// Sets up hook and replaces the vtable with new one
		/// </summary>
		/// <returns>Returns true if hooks was successfully initialized
		bool init()
		{
			if ( !m_vtable )
				return false;

			INIT_MEM_PROTECT_RW( m_vtable, sizeof( uintptr_t ) );

			/// Store old vtable
			m_orig = *m_vtable;

			m_table_length = mem::get_vtable_length( m_orig );

			/// Either faulty vtable or function fail
			if ( !m_table_length )
				return false;

			/// Allocate new vtable ( +1 for RTTI )
			m_replace = std::make_unique<uintptr_t[]>( m_table_length + 1 );

			/// instantiate all values with 0
			std::memset( m_replace.get(),
						 NULL,
						 m_table_length * sizeof( uintptr_t ) + sizeof( uintptr_t ) );

			/// The following two memcpy's could be just made 
			/// into 1 call but for demonstration purposes
			/// I'll leave it like that

			/// Copy old table
			/// Skip first 4/8 bytes to later insert RTTI there
			std::memcpy( &m_replace[ 1 ],
						 m_orig,
						 m_table_length * sizeof( uintptr_t ) );

			/// Copy RTTI
			std::memcpy( m_replace.get(),
						 &m_orig[ -1 ],
						 sizeof( uintptr_t ) );

			/// Apply new vtable, again skipping the first 4/8
			/// bytes since that's where the RTTI is now located
			*m_vtable = &m_replace[ 1 ];

			return true;
		}

		/// <summary>
		/// Hooks a given index
		/// </summary>
		/// <param name="index">
		/// Index of the function that should be replaced.
		/// Keep in mind that you have to +1 the index since 
		/// In the new vtable the RTTI is stored at the first index
		/// and thus all indexes are shifted by 1 
		/// </param>
		/// <param name="replace_function">The function which will be called instead of the original</param>
		void hook( const uint16_t index, void* replace_function )
		{
			/// Is index out of bounds?
			if ( index < 0 || index > m_table_length )
				return;

			m_replace[ index + 1 ] = reinterpret_cast< uintptr_t >( replace_function );
		}

		/// <summary>
		/// Gets a pointer to the original function with a given index
		/// </summary>
		/// <param name="index">Index of the function that should be retrieved</param>
		/// <returns>Returns the function pointer casted into a given function type</returns>
		template< typename t >
		t get_original( const uint16_t index )
		{
			/// Is index out of bounds?
			if ( index < 0 || index > m_table_length )
				return nullptr;

			return reinterpret_cast< t >( m_orig[ index ] );
		}

		/// <summary>
		/// Unhooks specific index
		/// </summary>
		/// <param name="index">Index of the function that should be unhooked</param>
		void unhook( const uint16_t index )
		{
			/// Is index out of bounds?
			if ( index < 0 || index > m_table_length )
				return;

			m_replace[ index + 1 ] = m_orig[ index ];
		}

		/// <summary>
		/// Restore old vtable and thus unhook all functions
		/// </summary>
		void unhook()
		{
			/// Check if it was already restored
			if ( !m_orig )
				return;

			INIT_MEM_PROTECT_RW( m_vtable, sizeof( uintptr_t ) );

			*m_vtable = m_orig;

			/// Prevent double unhook
			m_orig = nullptr;
		}

		/// <summary>
		/// The vtable that is being modified
		/// </summary>
		uintptr_t** m_vtable;

		/// <summary>
		/// Amount of all functions within the vtable
		/// </summary>
		uint16_t m_table_length;

		/// <summary>
		/// Pointer to the original vtable
		/// </summary>
		uintptr_t* m_orig;

		/// <summary>
		/// New custom vtable
		/// </summary>
		std::unique_ptr<uintptr_t[]> m_replace;
	};
}