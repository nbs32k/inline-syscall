# inline-syscall
Header-only library for the MSVC compiler allowing to generate direct syscalls, supporting both x86 and x64 platforms and both ntoskrnl and win32k services (ntdll & win32u).

# System calls callback
After executing the `syscall` instruction, users can inject malicious code into your program to monitor the request. This type of code can modify or sniff the request.
If you know what you are doing and you are looking forward to monitor the syscall, uncomment [line 3](https://github.com/n00bes/inline-syscall/blob/73a0d098155a0f22a8566b63a611546016f0947a/inline_syscall.hpp#L3) to prevent the killing of any callback insertion.

Otherwise, if you want to casually execute a syscall, don't touch the comment!
# Why?
Well, there are a lot of reasons. MSVC supports inline assembly just for the x86, so executing inline syscalls on x64 is a nono. Writing fixed syscall indexes isn't safe as they might change from build to build.

This library allows easy inlining for both x86 and x64 and also supports the win32k service table (gdi, user32 functions).
It is also very lightweight.

# How to use
Include the header and initialize the library by creating an object `inline_syscall inliner;`.
To invoke a system call, use the object created with the `inliner.invoke<returnType>("NtXxX", ...)` function.

To check if the inliner has been correctly initialized, the return of the function `is_init()` has to be `IS_SUCCESS`/`0`.
You can also check for errors occured while trying to call a service. The error gets set in the `last_error` field in the `inline_syscall` class and can be retrieved through the `get_error()` function.

Error code list:
```cpp
#define IS_ADDRESS_NOT_FOUND -1
#define IS_CALLBACK_KILL_FAILURE -2
#define IS_INTEGRITY_STUB_FAILURE -3
#define IS_MODULE_NOT_FOUND -4
#define IS_ALLOCATION_FAILURE -5
#define IS_INIT_NOT_APPLIED -6
#define IS_SUCCESS 0
```

# C++ Code examples

<details>

<summary>ntdll.dll</summary>

```cpp
#include "inline_syscall.hpp"

typedef struct _IO_STATUS_BLOCK
{
	union
	{
		NTSTATUS Status;
		PVOID    Pointer;
	};
	ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

void my_thread( ) {

	NTSTATUS s;
	inline_syscall inliner;

	while( 1 )
	{
		s = inliner.invoke<NTSTATUS>( "NtYieldExecution" );
		printf( "NtYieldExecution: 0x%X, 0x%X\n", s, inliner.get_error() );
	}
		
}


int main( ) {
	
	HANDLE hCommon;
	NTSTATUS status;
	IO_STATUS_BLOCK iosb{};


	//
	//	Initialize the inliner
	//
	inline_syscall inliner;


	//
	//	Check if inliner is ready
	//
	if( !inliner.is_init( ) )
	{
		printf( "inline_syscall failed initialization (0x%X)!\n", inliner.get_error( ) );
		return 1;
	}


	//
	//	Initialize new thread
	//
	hCommon = CreateThread( 0, 0, ( LPTHREAD_START_ROUTINE )my_thread, 0, 0, 0 );
	if( hCommon == INVALID_HANDLE_VALUE )
	{
		printf( "couldn't create thread! (0x%X)\n", GetLastError( ) );
		return 1;
	}
	CloseHandle( hCommon );


	//
	//	Create handle to test.txt file
	//
	hCommon = CreateFileA( "test.txt", GENERIC_READ | GENERIC_WRITE,
				 FILE_SHARE_WRITE | FILE_SHARE_READ,
				 NULL,
				 CREATE_ALWAYS,
				 FILE_ATTRIBUTE_NORMAL,
				 NULL );

	if( hCommon == INVALID_HANDLE_VALUE )
	{
		printf( "couldn't create file! (0x%X)\n", GetLastError( ) );
		return 1;
	}
	

	//
	//	Allocate memory for content
	//	and write the file
	//
	BYTE* content = new BYTE[ 5 ];
	for( int i = 0; i < 1000; i++ )
	{
		
		sprintf( ( char* )content, "%03d\n", i );
		
		//
		//	Call service
		//
		status = inliner.invoke<NTSTATUS>( "NtWriteFile",
										   hCommon, 0, 0, 0,
										   &iosb, content,
										   4, 0, 0 );
		//
		//	Check if the invocation has succeeded
		//
		if( inliner.get_error( ) != IS_SUCCESS )
		{
			printf( "inline_syscall failed to call service (0x%X)!\n", inliner.get_error( ) );
			return 1;
		}

		//
		//	Print the status code
		//
		printf( "NtWriteFile: 0x%X\n", status );
	}
	CloseHandle( hCommon );

	inliner.unload( );
	

}
```
</details>

<details>

<summary>win32u.dll</summary>

```cpp
#include "inline_syscall.hpp"

int main( ) {

	NTSTATUS status;


	//
	//	Initialize the inliner
	//
	inline_syscall inliner;
	

	//
	//	Check if inliner is ready
	//
	if( !inliner.is_init( ) )
	{
		printf( "inline_syscall failed initialization (0x%X)!\n", inliner.get_error( ) );
		return 1;
	}


	//
	//	Call service
	//
	status = inliner.invoke<BOOL>( "NtUserSetCursorPos",
					GetSystemMetrics( 0 ) / 2,
					GetSystemMetrics( 1 ) / 2 );

	//
	//	Check if the invocation has succeeded
	//
	if( inliner.get_error( ) != IS_SUCCESS )
	{
		printf( "inline_syscall failed to call service (0x%X)!\n", inliner.get_error( ) );
		return 1;
	}

	//
	//	Print the status code
	//
	printf( "NtUserSetCursorPos %X\n", status );

	inliner.unload( );


}
```

</details>


# Unloading procedure
To unload, simply call the `unload();` procedure to free any allocated memory by the library.

