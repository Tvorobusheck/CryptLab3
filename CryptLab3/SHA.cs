using System;
using System.Collections.Generic;
using System.Text;
using System.IO;
using System.Security.Cryptography;

namespace CryptLab3
{
    class SHA
    {
        public static byte[] GetSHA(byte[] data)
        {
            using (SHA256 mySHA256 = SHA256.Create())
            {
                byte[] hashValue = mySHA256.ComputeHash(data);
                return hashValue;
            }
        }
    }
}
