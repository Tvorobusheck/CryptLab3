using System;
using System.Security.Cryptography;
using System.Text;
using CryptLab3.RSA;
using CryptLab3.Rijndael;
using System.Linq;

namespace CryptLab3
{
    class Program
    {
        
        static void Main(string[] args)
        {
            RSACryptoServiceProvider signatureRSA = new RSACryptoServiceProvider();

            // Генерация RSA ключей
            RSAParameters publicRSAKeyInfo, privateRSAKeyInfo;
            try
            {
                using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
                {
                    Byte[] buffer = RSA.ExportParameters(true).D;
                    string converted_D = BitConverter.ToString(buffer).Replace("-", "|");
                    buffer = RSA.ExportParameters(true).Modulus;
                    string converted_N = BitConverter.ToString(buffer).Replace("-", "|");
                    Console.WriteLine("Ключевая пара RSA: \n\tD=" + converted_D + ",\n\tN=" + converted_N);
                    publicRSAKeyInfo = RSA.ExportParameters(false);
                    privateRSAKeyInfo = RSA.ExportParameters(true);
                }
            }
            catch (ArgumentNullException)
            {
                Console.WriteLine("RSA шифрование провалилось.");
                return;
            }

            if (args.Length != 1 && args.Length != 2)
            {
                Console.WriteLine("Ожидалось 1 или 2 аргумента");
                return;
            }
            string fileContent = System.IO.File.ReadAllText(args[0]);
            byte[] sim_encrypted = { };
            byte[] keyRijndael = { };
            byte[] ivRijndael = { };
            byte[] senderSignature = { };
            byte[] originalSHA;
            // Шифруем документ с помощью симметричного шифрования AES(Rijndael)
            // Ключ шифрования AES шифруем с помощью RSA, используя его публичный ключ
            // Также генерируем цифровую подпись
            try
            {

                string original = fileContent;
                
                using (RijndaelManaged myRijndael = new RijndaelManaged())
                {

                    myRijndael.GenerateKey();
                    myRijndael.GenerateIV();
                    sim_encrypted = RijndaelEncrypter.EncryptStringToBytes(original, myRijndael.Key, myRijndael.IV);
                    Console.WriteLine("Исходный документ:   {0}", original);

                    keyRijndael = RSAEncrypter.RSAEncrypt(myRijndael.Key, publicRSAKeyInfo, false);
                    ivRijndael = RSAEncrypter.RSAEncrypt(myRijndael.IV, publicRSAKeyInfo, false);
                    // Генерация цифровой подписи
                    originalSHA = SHA.GetSHA(Encoding.UTF8.GetBytes(original));
                    senderSignature = RSAEncrypter.RSAEncrypt(SHA.GetSHA(Encoding.UTF8.GetBytes(original)), signatureRSA.ExportParameters(false), false);
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("Error: {0}", e.Message);
                return;
            }

            // Проверка цифровой подписи
            byte[] encryptedSignature = RSADecrypter.RSADecrypt(senderSignature, signatureRSA.ExportParameters(true), false);
            if (!Enumerable.SequenceEqual(encryptedSignature, originalSHA))
            {
                Console.WriteLine("Ненастоящая цифровая подпись");
                return;
            }


            // Вначале расшифровываем параметры симметричного шифрования с помощью закрытого ключа. 
            // А потом используем полученный ключ AES для расшифровки основного текста
            string roundtrip = RijndaelDecrypter.DecryptStringFromBytes(sim_encrypted, 
                RSADecrypter.RSADecrypt(keyRijndael, privateRSAKeyInfo, false),
                RSADecrypter.RSADecrypt(ivRijndael, privateRSAKeyInfo, false));
            Console.WriteLine("Расшифрованный текст: {0}", roundtrip);

        }
    }
}
