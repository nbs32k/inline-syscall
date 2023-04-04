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

# Code example
Include the header and initialize the library by calling `inline_syscall::init( )` function.

To invoke a system call, use the `inline_syscall::invoke<returnType>(NtXxX, ...)` function.

* ntoskrnl.exe system service example of writing to a file:
```cpp
#include "inline_syscall.hpp"
int main( ) {

    NTSTATUS Status;
    HANDLE hHandle;
    IO_STATUS_BLOCK IoBlock;

    Status = inline_syscall::init( );
    printf( "inline_syscall::init( ): %x\n", Status );

    hHandle = CreateFileA(
        "C:\\Users\\leet\\Desktop\\test.txt",
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_WRITE | FILE_SHARE_READ,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    
    BYTE* pog = new BYTE[ 512 ];
    memset( pog, 0x69, 512 );

    Status = inline_syscall::invoke<NTSTATUS>(
        "NtWriteFile",
        hHandle,
        0,
        0,
        0,
        &IoBlock,
        pog,
        512,
        0,
        0
        );
    printf( "inline_syscall::invoke( ): %x\n", Status );

    CloseHandle( hHandle );

    inline_syscall::unload( );
}
```

* win32k.sys system service example of setting the cursor position:
```cpp
#include "inline_syscall.hpp"
int main( ) {

    NTSTATUS Status;


    Status = inline_syscall::init( );
    printf( "inline_syscall::init( ): %x\n", Status );

    Status = inline_syscall::invoke< BOOL >(
        "NtUserSetCursorPos",
        GetSystemMetrics( 0 ) / 2,
        GetSystemMetrics( 1 ) / 2 );
    printf( "inline_syscall::invoke( ): %x\n", Status );

    inline_syscall::unload( );
}
```

# Unloading procedure
To unload, simply call the `inline_syscall::unload();` procedure to free any allocated memory by the library.

# Demonstration


https://user-images.githubusercontent.com/68382500/229877717-f827703a-be86-4056-9258-ec017597d645.mp4

