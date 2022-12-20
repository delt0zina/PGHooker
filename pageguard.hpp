#pragma once

#include <Windows.h>
#include <list>

#ifdef _WIN64
#define get_page(ptr) (ptr & 0xFFFFFFFFFFFFF000)
#else
#define get_page(ptr) (ptr & 0xFFFFF000)
#endif

enum e_callback_flags : int
{
	flag_read = 1 << 0,
	flag_write = 1 << 1,
};

enum e_exception_info_zero : int
{
	info_read,
	info_write,
	info_depvio = 8,
};

typedef void ( __fastcall* callback_t )( PCONTEXT context, e_callback_flags type );

class c_callback_info
{
public:
#ifdef _WIN64
	uint64_t m_address {};
#else
	uint32_t m_address {};
#endif

	callback_t m_callback {};
	e_callback_flags m_flags {};
};

class c_hook_info
{
public:
#ifdef _WIN64
	uint64_t m_redirect_from {};
	uint64_t m_redirect_to {};
#else
	uint32_t m_redirect_from {};
	uint32_t m_redirect_to {};
#endif

	void** m_original { };

	bool m_once_disabled {};
};

namespace pageguard
{
	inline std::list < c_callback_info > callbacks_info { };
	inline std::list < c_hook_info > hooks_info { };
	inline void* exception_handler_handle { };

	static void set_page_guard_protect ( const void* address )
	{
		DWORD old_protect { };
		MEMORY_BASIC_INFORMATION mbi { };
		SYSTEM_INFO system_info { };

		GetSystemInfo ( &system_info );
		VirtualQuery ( address, &mbi, sizeof ( MEMORY_BASIC_INFORMATION ) );
		VirtualProtect ( ( LPVOID ) address, system_info.dwPageSize, mbi.Protect | PAGE_GUARD, &old_protect );
	}

	static void remove_page_guard_protect ( const void* address )
	{
		DWORD old_protect { };
		MEMORY_BASIC_INFORMATION mbi { };
		SYSTEM_INFO system_info { };

		GetSystemInfo ( &system_info );
		VirtualQuery ( address, &mbi, sizeof ( MEMORY_BASIC_INFORMATION ) );
		VirtualProtect ( ( LPVOID ) address, system_info.dwPageSize, mbi.Protect & ~PAGE_GUARD, &old_protect );
	}

	static LONG WINAPI exception_handler ( PEXCEPTION_POINTERS exception_info )
	{
#ifdef _WIN64
		uint64_t address = exception_info->ContextRecord->Rip;
#else
		uint32_t address = exception_info->ContextRecord->Eip;
#endif

		if ( exception_info->ExceptionRecord->ExceptionCode == EXCEPTION_GUARD_PAGE )
		{
			ULONG_PTR type = exception_info->ExceptionRecord->ExceptionInformation [ 0 ];

			if ( type == e_exception_info_zero::info_read || type == e_exception_info_zero::info_write )
			{
				address = exception_info->ExceptionRecord->ExceptionInformation [ 1 ];

				for ( auto& callback : callbacks_info )
				{
					if ( address != callback.m_address )
						continue;

					e_callback_flags flag = e_callback_flags ( 1 << type );

					if ( !( callback.m_flags & flag ) )
						continue;

					callback.m_callback ( exception_info->ContextRecord, flag );
				}
			}
			else if ( type == e_exception_info_zero::info_depvio )
			{
				for ( auto& hook : hooks_info )
				{
					if ( address != hook.m_redirect_from )
						continue;

					if ( hook.m_once_disabled )
					{
						hook.m_once_disabled = false;
						continue;
					}

#ifdef _WIN64
					*hook.m_original = reinterpret_cast < void* > ( exception_info->ContextRecord->Rip );
					exception_info->ContextRecord->Rip = hook.m_redirect_to;
#else
					*hook.m_original = reinterpret_cast < void* > ( exception_info->ContextRecord->Eip );
					exception_info->ContextRecord->Eip = hook.m_redirect_to;
#endif
					break;
				}
			}

			exception_info->ContextRecord->EFlags |= 0x100ui32;

			return EXCEPTION_CONTINUE_EXECUTION;
		}
		else if ( exception_info->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP )
		{
			for ( auto& hook : hooks_info )
			{
				if ( address != hook.m_redirect_from )
					continue;

				set_page_guard_protect ( reinterpret_cast < void* > ( hook.m_redirect_from ) );
				break;
			}

			return EXCEPTION_CONTINUE_EXECUTION;
		}

		return EXCEPTION_CONTINUE_SEARCH;
	}

	static void init ( )
	{
		exception_handler_handle = AddVectoredExceptionHandler ( TRUE, exception_handler );
	}

	static void destroy ( )
	{
		for ( auto& hook : hooks_info )
			remove_page_guard_protect ( reinterpret_cast < void* > ( hook.m_redirect_from ) );
		for ( auto& callback : callbacks_info )
			remove_page_guard_protect ( reinterpret_cast < void* > ( callback.m_address ) );

		callbacks_info.clear ( );
		hooks_info.clear ( );

		RemoveVectoredExceptionHandler ( exception_handler_handle );
	}

	static void create_hook ( const void* from, const void* to, void** original )
	{
		bool guard = true;

#ifdef _WIN64
		uint64_t from_address = reinterpret_cast < uint64_t > ( from );
		uint64_t to_address = reinterpret_cast < uint64_t > ( to );
#else
		uint32_t from_address = reinterpret_cast < uint32_t > ( from );
		uint32_t to_address = reinterpret_cast < uint32_t > ( to );
#endif

		for ( auto& info : hooks_info )
		{
			if ( info.m_redirect_from == from_address )
				return;

			if ( get_page ( info.m_redirect_from ) == get_page ( from_address ) )
				guard = false;
		}

		hooks_info.push_back ( { from_address, to_address, original, false } );

		if ( guard )
			set_page_guard_protect ( from );
	}

	static void remove_hook ( const void* from )
	{
#ifdef _WIN64
		uint64_t from_address = reinterpret_cast < uint64_t > ( from );
#else
		uint32_t from_address = reinterpret_cast < uint32_t > ( from );
#endif

		std::list < c_hook_info >::iterator i = hooks_info.begin ( );
		bool removed = false;

		while ( i != hooks_info.end ( ) )
		{
			if ( i->m_redirect_from == from_address )
			{
				hooks_info.erase ( i );
				removed = true;
				break;
			}

			++i;
		}

		if ( !removed )
			return;

		bool unguard = true;

		for ( auto& info : hooks_info )
		{
			if ( get_page ( info.m_redirect_from ) == get_page ( from_address ) )
			{
				unguard = false;
				break;
			}
		}

		if ( unguard )
			remove_page_guard_protect ( from );
	}

	static void create_callback ( const void* address, e_callback_flags flags, callback_t callback )
	{
		bool guard = true;

#ifdef _WIN64
		uint64_t address_from = reinterpret_cast < uint64_t > ( address );
#else
		uint32_t address_from = reinterpret_cast < uint32_t > ( address );
#endif

		for ( auto& info : callbacks_info )
		{
			if ( get_page ( info.m_address ) == get_page ( address_from ) )
			{
				guard = false;
				break;
			}
		}

		callbacks_info.push_back ( { address_from, callback, flags } );

		if ( guard )
			set_page_guard_protect ( address );
	}

	void remove_callback ( const void* address )
	{
		std::list < c_callback_info >::iterator i = callbacks_info.begin ( );
		bool removed = false;

#ifdef _WIN64
		uint64_t address_from = reinterpret_cast < uint64_t > ( address );
#else
		uint32_t address_from = reinterpret_cast < uint32_t > ( address );
#endif

		while ( i != callbacks_info.end ( ) )
		{
			if ( i->m_address == address_from )
			{
				i = callbacks_info.erase ( i );
				removed = true;
			}
			else
				++i;
		}

		if ( !removed )
			return;

		bool unguard = true;

		for ( auto& info : callbacks_info )
		{
			if ( get_page ( info.m_address ) == get_page ( address_from ) )
			{
				unguard = false;
				break;
			}
		}

		if ( unguard )
			remove_page_guard_protect ( address );
	}
}
