#pragma once
#include <Windows.h>
//#define _ALLOW_MONITOR

#define IS_ADDRESS_NOT_FOUND -1
#define IS_CALLBACK_KILL_FAILURE -2
#define IS_INTEGRITY_STUB_FAILURE -3
#define IS_MODULE_NOT_FOUND -4
#define IS_ALLOCATION_FAILURE -5
#define IS_INIT_NOT_APPLIED -6
#define IS_SUCCESS 0

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)



HINSTANCE hSubsystemInstances[ 2 ];

class inline_syscall
{

	public:

		inline_syscall( );
		void unload( );
		void callback( );

		void set_error( int error_code ) {
			last_error = error_code;
		}

		int get_error( ) {
			return last_error;
		}

		bool is_init( ) {
			return initialized;
		}

		UCHAR* get_stub(  ) {
			return syscall_stub;
		}
		

		template <typename returnType, typename ...args>
		returnType invoke( LPCSTR ServiceName, args... arguments );

	private:
		int last_error;
		bool initialized;
		UCHAR* syscall_stub;

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



inline_syscall::inline_syscall( ) {

	NTSTATUS Status;
	UINT i;

	initialized = 0;
	syscall_stub = 0;
	last_error = IS_INIT_NOT_APPLIED;


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
		{
			last_error = IS_MODULE_NOT_FOUND;
			return;
		}
			





	//
	//	Setup the system call stub
	//	as in NTDLL.DLL services
	//
	syscall_stub = ( UCHAR* )VirtualAlloc( NULL, 21, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );
	if( syscall_stub == nullptr )
	{
		last_error = IS_CALLBACK_KILL_FAILURE;
		return;
	}
		

#ifdef _M_X64
	//
	//	Syscall stub shellcode
	//
	memcpy( syscall_stub, "\x4C\x8B\xD1\xB8\x00\x00\x00\x00\x0F\x05\xC3", 11 );
#endif



	//
	//	Try killing callbacks
	//

#ifndef _ALLOW_MONITOR
	callback( );
	if( last_error != IS_SUCCESS )
		return;
		
#endif

	last_error = IS_SUCCESS;
	initialized = 1;
}

void inline_syscall::callback( ) {

	//
	//	Kill any system call callback
	//

	NTSTATUS Status;
	pNtSetInformationProcess* NtSetInformationProcess;
	PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION SyscallCallback;



	NtSetInformationProcess = ( pNtSetInformationProcess* )GetProcAddress( hSubsystemInstances[ 0 ], "NtSetInformationProcess" );
	if( NtSetInformationProcess == nullptr )
	{
		inline_syscall::set_error( IS_ADDRESS_NOT_FOUND );
		return;
	}
	


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
	{
		inline_syscall::set_error( IS_CALLBACK_KILL_FAILURE );
		return;
	}
		

	inline_syscall::set_error( IS_SUCCESS );

}

VOID inline_syscall::unload( ) {

	if( inline_syscall::syscall_stub == nullptr )
		return;

	memset( inline_syscall::syscall_stub, 0, 21 );
	VirtualFree( inline_syscall::syscall_stub, 0, MEM_RELEASE );

}

template <typename returnType, typename ...args>
returnType inline_syscall::invoke( LPCSTR ServiceName, args... arguments ) {

	NTSTATUS Status;
	UCHAR* FunctionAddress;
	INT SystemCallIndex;

	UINT i;

	if( !inline_syscall::initialized )	// Initialization not applied?
	{
		inline_syscall::set_error( IS_INIT_NOT_APPLIED );
		return IS_INIT_NOT_APPLIED;
	}




#ifndef _ALLOW_MONITOR

	//
	//	Kill monitoring callback
	//
	inline_syscall::callback( );
#endif



	typedef returnType __stdcall NtFunction( args... );
	NtFunction* Function = ( NtFunction* )inline_syscall::syscall_stub;

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
			{
				inline_syscall::set_error( IS_INTEGRITY_STUB_FAILURE );
				return IS_INTEGRITY_STUB_FAILURE;
			}


			//
			//	NtXxX + 0x4 = Syscall Index (unsigned int)
			//
			SystemCallIndex = ( UINT )FunctionAddress[ 4 ];
			memcpy( inline_syscall::get_stub( ) + 0x4, &SystemCallIndex, sizeof( UINT ) );


			//
			//	If i points to win32k.sys call
			//	copy the whole stub because x86 contains additional opcodes (jne xxx)
			//
			if( i == 1 )
				memcpy( inline_syscall::get_stub( ), FunctionAddress, 21 );


		#else

			//
			//	Small check against modified stubs
			//	I'd call it an integrity check because we copy the whole stub
			//
			if( FunctionAddress[ 0 ] != 0xB8 &&
				FunctionAddress[ 5 ] != 0xBA ) // mov eax, index \x??\x??\x??\x?? mov edx, KiFastSystemCall
				return ( returnType )IS_INTEGRITY_STUB_FAILURE;

			memcpy( inline_syscall::get_stub( ), FunctionAddress, 15 );
		#endif

			inline_syscall::set_error( IS_SUCCESS );
			return Function( arguments... );
		}


	}
	inline_syscall::set_error( IS_MODULE_NOT_FOUND );
	return IS_MODULE_NOT_FOUND;


}

