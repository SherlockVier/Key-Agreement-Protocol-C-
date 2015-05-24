using System;
using System.Text;
using System.Collections;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace Sender
{
    public class RSA
    {
        public static string EncryptPublicKey(string publicKey,string dataToEncrypt)
        {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            rsa.FromXmlString(publicKey);
            byte[] encryptedData = rsa.Encrypt(Encoding.UTF8.GetBytes(dataToEncrypt), false);
            return Convert.ToBase64String(encryptedData);
        }

        public static string DecryptPrivateKey(string privateKey,string dataToDecrypt)
        {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            byte[] decryptedData;
            byte[] data = Convert.FromBase64String(dataToDecrypt);
            rsa.FromXmlString(privateKey);
            decryptedData = rsa.Decrypt(data, false);
            return Encoding.UTF8.GetString(decryptedData);
        }

        public static string CreateRandom()
        {
            SHA1 sha1 = new SHA1CryptoServiceProvider();
            string time = DateTime.Now.ToString();
            byte[] source = Encoding.Default.GetBytes(time);
            byte[] crypto = sha1.ComputeHash(source);
            return BitConverter.ToString(crypto);
        }
    }
}
