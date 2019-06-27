using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;

namespace Insurance.Business.Services
{
    /// <summary>加解密服務</summary>
    public class CryptoService
    {
        /// <summary>AES 加密方式</summary>
        public class AesCrypto
        {
            private static Encoding encoding = Encoding.Unicode;

            private static int _blockSize = 128;
            private static int _keySize = 256;
            private static string _encKey = "d903jk10(*3l39)#";

            /// <summary>加密</summary>
            /// <param name="plainText"></param>
            /// <returns></returns>
            public static string Encrypt(string plainText)
            {
                if (string.IsNullOrWhiteSpace(plainText))
                    return string.Empty;

                byte[] encrypted;

                var keyBytes = encoding.GetBytes(_encKey);

                var encodeBytes = encoding.GetBytes(plainText);
                using (AesManaged aes = new AesManaged())
                {
                    aes.BlockSize = _blockSize;
                    aes.KeySize = _keySize;
                    aes.GenerateIV();
                    aes.Key = keyBytes;
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.ANSIX923;
                    using (var enc = aes.CreateEncryptor())
                    using (MemoryStream ms = new MemoryStream())
                    using (CryptoStream writer = new CryptoStream(ms, enc, CryptoStreamMode.Write))
                    {
                        writer.Write(encodeBytes, 0, encodeBytes.Length);
                        writer.FlushFinalBlock();
                        var crypto = ms.ToArray();

                        encrypted = new byte[crypto.Length + aes.IV.Length];
                        Array.Copy(crypto, encrypted, crypto.Length);
                        Array.Copy(aes.IV, 0, encrypted, crypto.Length, aes.IV.Length);
                    }

                    aes.Clear();

                    return Convert.ToBase64String(encrypted);
                }
            }

            /// <summary>解密</summary>
            /// <param name="encryptText"></param>
            /// <returns></returns>
            public static string Decrypt(string encryptText)
            {
                if (string.IsNullOrWhiteSpace(encryptText))
                    return string.Empty;

                var keyBytes = encoding.GetBytes(_encKey);
                var encryptBytes = Convert.FromBase64String(encryptText);

                var result = string.Empty;
                using (AesManaged aes = new AesManaged())
                {
                    aes.BlockSize = _blockSize;
                    aes.KeySize = _keySize;
                    aes.Key = keyBytes;
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.ANSIX923;
                    // get iv from encoded bytes
                    byte[] ivBytes = new byte[_blockSize / 8];
                    Array.Copy(encryptBytes, encryptBytes.Length - ivBytes.Length, ivBytes, 0, ivBytes.Length);
                    aes.IV = ivBytes;
                    // copy encrypted data bytes
                    byte[] cryptoBytes = new byte[encryptBytes.Length - ivBytes.Length];
                    Array.Copy(encryptBytes, cryptoBytes, cryptoBytes.Length);

                    using (var dec = aes.CreateDecryptor())
                    using (MemoryStream ms = new MemoryStream(cryptoBytes))
                    using (CryptoStream cs = new CryptoStream(ms, dec, CryptoStreamMode.Read))
                    {
                        var plainByte = new byte[encryptBytes.Length - ivBytes.Length];
                        var cnt = cs.Read(plainByte, 0, plainByte.Length);
                        aes.Clear();
                        result = SecureStringToString(GenSecureString(encoding.GetString(plainByte, 0, cnt)));
                    }
                }
                return result;
            }

        }

        /// <summary>
        /// 產生SecureString
        /// </summary>
        /// <param name="source">要加密的字串</param>
        /// <returns></returns>
        public static SecureString GenSecureString(string source)
        {
            var sourceArr = source.ToCharArray();
            var securePwd = new SecureString();
            for (int i = 0; i < sourceArr.Length; i++)
                securePwd.AppendChar(sourceArr[i]);
            return securePwd;
        }
        /// <summary>
        /// 將SecureString轉為字串
        /// </summary>
        /// <param name="value">要解密的字串</param>
        /// <returns></returns>
        public static String SecureStringToString(SecureString value)
        {
            IntPtr valuePtr = Marshal.SecureStringToGlobalAllocUnicode(value);
            var sb = new System.Text.StringBuilder(1000);
            try
            {

                for (Int32 i = 0; i < value.Length; i++)
                {
                    // multiply 2 because Unicode chars are 2 bytes wide
                    Char ch = (Char)Marshal.ReadInt16(valuePtr, i * 2);
                    // do something with each char
                    sb.Append(ch);
                }

                return sb.ToString();
            }
            finally
            {
                Marshal.ZeroFreeGlobalAllocUnicode(valuePtr);
            }
        }
    }
}
