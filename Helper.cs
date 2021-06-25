∩╗┐using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Helper
{
    class Program
    {
        static byte[] Encrypt(byte[] data,string Key, string IV)
        {
            AesCryptoServiceProvider dataencrypt = new AesCryptoServiceProvider();
            dataencrypt.BlockSize = 128;
            dataencrypt.KeySize = 128;
            dataencrypt.Key = System.Text.Encoding.UTF8.GetBytes(Key);
            dataencrypt.IV = System.Text.Encoding.UTF8.GetBytes(IV);
            dataencrypt.Padding = PaddingMode.PKCS7;
            dataencrypt.Mode = CipherMode.CBC;
            ICryptoTransform crypto1 = dataencrypt.CreateEncryptor(dataencrypt.Key, dataencrypt.IV);
            byte[] encrypteddata = crypto1.TransformFinalBlock(data, 0, data.Length);
            crypto1.Dispose();
            return encrypteddata;
        }

        static byte[] xor_enc(byte[] shellcode, string pass)
        {
            byte[] key = Encoding.ASCII.GetBytes(pass);
            byte[] enc_shelcode = new byte[shellcode.Length];
            int j = 0;
            for (int i = 0; i < shellcode.Length; i++)
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
            if (args[0].StartsWith("-location") && args[1].StartsWith("-encrypt") && args[2].StartsWith("-password") && args[3].StartsWith("-saveTo"))
            {
                string location = args[0].Split('=')[1];
                string algo = args[1].Split('=')[1];
                string pass = args[2].Split('=')[1];
                string writeTo = args[3].Split('=')[1];

                byte[] shellcode = File.ReadAllBytes(location);
                if (algo == "aes")
                {
                    byte[] encoded_shellcode = Encrypt(shellcode, pass,"1234567891234567");
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
