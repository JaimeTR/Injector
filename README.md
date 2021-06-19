# Injector
Complete Arsenal of Memory injection and other techniques for red-teaming in Windows

# What does Injector do?

- Process injection support for shellcode located at remote server as well as local storage. Just specify the shellcode file and it will do the rest. It will by default inject into notepad.exe and if not found, it will create a notepad process and inject into it for persistence.

- Reflective DLL Injection for DLL injection. It downloads the DLL and injects into remote process.
- Process hollowing via svchosts.exe

```
C:\Users\admin>Injector.exe
Help Options for Xenon:
-m       Mode of operation
        -m 1     Specifies the mode as Process injection
        -m 2     Specifies the mode as Reflective DLL Injection
        -m 3     Specifies the mode as Process Hollowing

-shellcode       Use shellcode
-dll     Use dll
-location        Specify the location i.e either server or local
```
