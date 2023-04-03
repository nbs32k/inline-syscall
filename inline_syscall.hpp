#pragma once
#include <Windows.h>
//#define _ALLOW_MONITOR


#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

HINSTANCE hSubsystemInstances[ 2 ];
UCHAR* SystemCallStub;

class inline_syscall
{

	public:

		static int init( );
		static void unload( );
		static int callback( );

		template <typename returnType, typename ...args>
		static returnType invoke( LPCSTR ServiceName, args... arguments );

	private:

		typedef NTSTATUS __stdcall pNtSetInformationProcess(
			HANDLE ProcessHandle,
			PROCESS_INFORMATION_CLASS ProcessInformationClass,
			PVOID ProcessInformation,
			ULONG ProcessInformationLength
			);

		struct PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION
		{
			ULONG Version;
			ULONG Reserved;
			PVOID Callback;
		};

};

int inline_syscall::callback( ) {

	//
	//	Kill any system call callback
	//

	NTSTATUS Status;
	pNtSetInformationProcess* NtSetInformationProcess;
	PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION SyscallCallback;



	NtSetInformationProcess = ( pNtSetInformationProcess* )GetProcAddress( hSubsystemInstances[ 0 ], "NtSetInformationProcess" );
	if( NtSetInformationProcess == nullptr )
		return -1;


	//
	//	Disable any callbacks caused by the syscall instruction
	//	( Prevents monitoring of the syscall )
	//
	SyscallCallback.Reserved = 0;
	SyscallCallback.Version = 0;
	SyscallCallback.Callback = NULL;

	Status = NtSetInformationProcess(
		GetCurrentProcess( ),
		( PROCESS_INFORMATION_CLASS )40,
		&SyscallCallback,
		sizeof( SyscallCallback ) );

	if( !NT_SUCCESS( Status ) )
		return -2;


	return 0;

}

int inline_syscall::init( ) {


	NTSTATUS Status;
	


	hSubsystemInstances[ 0 ] = LoadLibraryA( "ntdll.dll" );
	hSubsystemInstances[ 1 ] = LoadLibraryA( "win32u.dll" );

	for( int i = 0; i < sizeof hSubsystemInstances / sizeof HINSTANCE; i++ )
		if( hSubsystemInstances[ i ] == nullptr )
			return -1;


	


	//
	//	Setup the system call stub
	//  as in NTDLL.DLL services
	//
	SystemCallStub = ( UCHAR* )VirtualAlloc( NULL, 21, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );
	if( SystemCallStub == nullptr )
		return -3;

#ifdef _M_X64
	memcpy( SystemCallStub, "\x4C\x8B\xD1\xB8\x00\x00\x00\x00\x0F\x05\xC3", 11 );
#endif



	//
	//	Try killing callbacks
	//

#ifndef _ALLOW_MONITOR
	if( inline_syscall::callback( ) != 0 )
		return -4;
#endif

	return 0;	// Success

}

void inline_syscall::unload( ) {

	if( SystemCallStub == nullptr )
		return;

	memset( SystemCallStub, 0, 21 );
	VirtualFree( SystemCallStub, 0, MEM_RELEASE );

}

template <typename returnType, typename ...args>
returnType inline_syscall::invoke( LPCSTR ServiceName, args... arguments ) {

	NTSTATUS Status;
	UCHAR* FunctionAddress;
	INT SystemCallIndex;

	if( SystemCallStub == nullptr )
		return ( returnType )0;



#ifndef _ALLOW_MONITOR

	//
	//	Kill monitoring callback
	//
	inline_syscall::callback( );
#endif



	typedef returnType __stdcall NtFunction( args... );
	NtFunction* Function = ( NtFunction* )SystemCallStub;

	for( UINT i = 0; i < sizeof hSubsystemInstances / sizeof HINSTANCE; ++i )
	{

		//
		//	Get the address
		//
		FunctionAddress = ( UCHAR* )GetProcAddress( hSubsystemInstances[ i ], ServiceName );


		//
		//	Prepare to execute
		//
		if( FunctionAddress != nullptr )
		{

		#ifdef _M_X64

			//
			//	NtXxX + 0x4 = Syscall Index (unsigned int)
			//
			SystemCallIndex = ( UINT )FunctionAddress[ 4 ];
			memcpy( SystemCallStub + 0x4, &SystemCallIndex, sizeof( UINT ) );


			if( i == 1 )	// if Win32U.dll: additional opcodes, requires copy of whole stub
				memcpy( SystemCallStub, FunctionAddress, 21 );
				
			
		#else
			if( i == 1 )	// Broken calls for x86
				return ( returnType )0;

			memcpy( SystemCallStub, FunctionAddress, 15 );
		#endif
			
			return Function( arguments... );
		}

			
	}


	return ( returnType )0;
	

}

