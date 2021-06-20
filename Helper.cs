using System;
using System.Text;
using System.Security.Cryptography;
using System.IO;

namespace Helper
{
    class Program
    {
        static byte[] Encrypt(byte[] data,string password)
        {
            byte[] m_Key = Encoding.ASCII.GetBytes(password);
            byte[] m_IV = Encoding.ASCII.GetBytes("123456");
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            using (var rijndaelManaged = new RijndaelManaged())
            {
                rijndaelManaged.KeySize = m_Key.Length * 8;
                rijndaelManaged.Key = m_Key;
                rijndaelManaged.BlockSize = m_IV.Length * 8;
                rijndaelManaged.IV = m_IV;

                using (var encryptor = rijndaelManaged.CreateEncryptor())
                using (var ms = new MemoryStream())
                using (var cryptoStream = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                {
                    cryptoStream.Write(data, 0, data.Length);
                    cryptoStream.FlushFinalBlock();

                    return ms.ToArray();
                }
            }
        }

        static byte[] xor_enc(byte[] shellcode,string pass)
        {
            byte[] key = Encoding.ASCII.GetBytes(pass);
            byte[] enc_shelcode = new byte[shellcode.Length];
            int j = 0;
            for(int i = 0; i < shellcode.Length; i++)
            {
                if (j >= key.Length)
                {
                    j = 0;
                }
                enc_shelcode[i] = (byte)(((uint)shellcode[i] ^ (uint)key[j]) & 0xff);
            }
            return enc_shelcode;
        }

        static void help_me()
        {
            Console.WriteLine("Helper.exe \n-location=<local_storage_of_raw_shellcode> \n-encrypt=<aes/xor> \n-password=<pass> \n-saveTo=<writeToFile>");
            return;
        }

        static void Main(string[] args)
        {
	    if(args.Length != 5){
		    help_me();
		    return;
	    }
            if (args[1].StartsWith("-location") && args[2].StartsWith("-encrypt") && args[3].StartsWith("-password") && args[4].StartsWith("-saveTo"))
            {
                string location = args[1].Split('=')[1];
                string algo = args[2].Split('=')[1];
                string pass = args[3].Split('=')[1];
                string writeTo = args[4].Split('=')[1];

                byte[] shellcode = File.ReadAllBytes(location);
                if (algo == "aes")
                {
                    byte[] encoded_shellcode = Encrypt(shellcode, pass);
                    File.WriteAllBytes(writeTo, encoded_shellcode);
                    Console.WriteLine("[+] Encrypted aes shellcode written to disk");
                    return;
                }
                else if (algo == "xor")
                {
                    byte[] encoded_shellcode = xor_enc(shellcode, pass);
                    File.WriteAllBytes(writeTo, encoded_shellcode);
                    Console.WriteLine("[+] Encrypted xor shellcode written to disk");
                    return;
                }
            }
            else
            {
                help_me();
                return;
            }
        }
    }
}

