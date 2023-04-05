#pragma once
#include <Windows.h>
//#define _ALLOW_MONITOR

#define IS_ADDRESS_NOT_FOUND -1
#define IS_CALLBACK_KILL_FAILURE -2
#define IS_INIT_FAILURE -3
#define IS_INTEGRITY_STUB_FAILURE -4
#define IS_MODULE_NOT_FOUND -5
#define IS_ALLOCATION_FAILURE -6
#define IS_INIT_NOT_APPLIED -7
#define IS_INCOMPATIBLE -8
#define IS_SUCCESS 0

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)



HINSTANCE hSubsystemInstances[ 2 ];
UCHAR* SystemCallStub;


class inline_syscall
{

	public:

		static INT init( );
		static VOID unload( );
		static INT callback( );

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

INT inline_syscall::callback( ) {

	//
	//	Kill any system call callback
	//

	NTSTATUS Status;
	pNtSetInformationProcess* NtSetInformationProcess;
	PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION SyscallCallback;



	NtSetInformationProcess = ( pNtSetInformationProcess* )GetProcAddress( hSubsystemInstances[ 0 ], "NtSetInformationProcess" );
	if( NtSetInformationProcess == nullptr )
		return IS_ADDRESS_NOT_FOUND;


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
		return IS_CALLBACK_KILL_FAILURE;


	return IS_SUCCESS;

}

INT inline_syscall::init( ) {


	NTSTATUS Status;
	UINT i;

	//
	//	Fill hSubsystemInstances
	//
	hSubsystemInstances[ 0 ] = LoadLibraryA( "ntdll.dll" );
	hSubsystemInstances[ 1 ] = LoadLibraryA( "win32u.dll" );

	//
	//	Could not load the modules??
	//
	for( i = 0; i < sizeof hSubsystemInstances / sizeof HINSTANCE; i++ )
		if( hSubsystemInstances[ i ] == nullptr )
			return IS_MODULE_NOT_FOUND;


	


	//
	//	Setup the system call stub
	//	as in NTDLL.DLL services
	//
	SystemCallStub = ( UCHAR* )VirtualAlloc( NULL, 21, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );
	if( SystemCallStub == nullptr )
		return IS_ALLOCATION_FAILURE;

#ifdef _M_X64
	//
	//	Syscall stub shellcode
	//
	memcpy( SystemCallStub, "\x4C\x8B\xD1\xB8\x00\x00\x00\x00\x0F\x05\xC3", 11 );
#endif



	//
	//	Try killing callbacks
	//

#ifndef _ALLOW_MONITOR
	if( inline_syscall::callback( ) != 0 )
		return IS_CALLBACK_KILL_FAILURE;
#endif

	return IS_SUCCESS;

}

VOID inline_syscall::unload( ) {

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

	UINT i;

	if( SystemCallStub == nullptr )	// Initialization not applied?
		return ( returnType )IS_INIT_NOT_APPLIED;



#ifndef _ALLOW_MONITOR

	//
	//	Kill monitoring callback
	//
	inline_syscall::callback( );
#endif


	
	typedef returnType __stdcall NtFunction( args... );
	NtFunction* Function = ( NtFunction* )SystemCallStub;

	for( i = 0; i < sizeof hSubsystemInstances / sizeof HINSTANCE; ++i )
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
			//	Small check against modified stubs
			//
			if( *( UINT* )FunctionAddress != 0xB8D18B4C ) //mov r10, rcx \ mov eax, index
				return ( returnType )IS_INTEGRITY_STUB_FAILURE;

			//
			//	NtXxX + 0x4 = Syscall Index (unsigned int)
			//
			SystemCallIndex = ( UINT )FunctionAddress[ 4 ];
			memcpy( SystemCallStub + 0x4, &SystemCallIndex, sizeof( UINT ) );


			//
			//	If i points to win32k.sys call
			//	copy the whole stub because x86 contains additional opcodes (jne xxx)
			//
			if( i == 1 )
				memcpy( SystemCallStub, FunctionAddress, 21 );
				
			
		#else

			//
			//	Small check against modified stubs
			//	I'd call it an integrity check because we copy the whole stub
			//
			if( FunctionAddress[ 0 ] != 0xB8 && 
				FunctionAddress[ 5 ] != 0xBA ) // mov eax, index \x??\x??\x??\x?? mov edx, KiFastSystemCall
				return ( returnType )IS_INTEGRITY_STUB_FAILURE;

			memcpy( SystemCallStub, FunctionAddress, 15 );
		#endif
			
			return Function( arguments... );
		}

			
	}


	return ( returnType )IS_MODULE_NOT_FOUND;
	

}

