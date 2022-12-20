#include <Windows.h>
#include "pageguard.hpp"

void __fastcall callback_test ( PCONTEXT ctx, e_callback_flags type )
{
	printf ( "-- CallbackRead0 \n" );
}

static decltype ( &MessageBoxA ) oMessageBox { };
int WINAPI hkMessageBoxA ( HWND hWnd,
						   LPCSTR lpText,
						   LPCSTR lpCaption,
						   UINT uType )
{
	printf ( "MessageBoxA hook called !!! \n" );

	return oMessageBox ( hWnd, lpText, "Hooked", uType );
}

auto main ( ) -> int
{
	pageguard::init ( );

	printf ( "RW hooking test \n--- \n" );
	{
		volatile int temp {};
		volatile int* mas = ( int* ) VirtualAlloc ( NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );

		pageguard::create_callback ( ( int* ) mas, e_callback_flags::flag_read, callback_test );

		printf ( "reading pMas[0] \n" );
		temp = mas [ 0 ];

		pageguard::remove_callback ( ( int* ) mas );
		pageguard::remove_callback ( ( int* ) mas + 1 );
	}

	printf ( "\nFunction hooking test \n--- \n" );
	{
		pageguard::create_hook ( MessageBoxA, hkMessageBoxA, reinterpret_cast < void** > ( &oMessageBox ) );

		printf ( "Calling MessageBoxA \n" );
		MessageBoxA ( NULL, "Text", "Caption", MB_ICONINFORMATION );

		pageguard::remove_hook ( MessageBoxA );
	}

	pageguard::destroy ( );
	printf ( "End! \n" );

infinite_loop:
	goto infinite_loop;

	return 0;
}
