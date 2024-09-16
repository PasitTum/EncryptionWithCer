using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

public class EncryptionByKey
{
    private readonly X509Certificate2 _certificate;
    private const string Delimiter = "::"; // ใช้แยก encrypted data และ encrypted key

    public EncryptionByKey(string thumbprint)
    {
        _certificate = GetCertificate(thumbprint);
    }

    private X509Certificate2 GetCertificate(string thumbprint)
    {
        using (X509Store store = new X509Store(StoreName.My, StoreLocation.LocalMachine))
        {
            store.Open(OpenFlags.ReadOnly);
            X509Certificate2Collection certs = store.Certificates.Find(X509FindType.FindBySubjectName, thumbprint, false);
            if (certs.Count > 0)
            {
                return certs[0];
            }
        }
        throw new Exception("Certificate not found");
    }

    public string Encrypt(string data)
    {
        using (Aes aes = Aes.Create())
        {
            // Encrypt data with AES
            byte[] encryptedData;
            using (MemoryStream ms = new MemoryStream())
            {
                using (CryptoStream cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    byte[] plainTextBytes = Encoding.UTF8.GetBytes(data);
                    cs.Write(plainTextBytes, 0, plainTextBytes.Length);
                }
                encryptedData = ms.ToArray();
            }

            // Encrypt AES key with RSA
            using (RSA rsa = _certificate.GetRSAPublicKey())
            {
                byte[] encryptedKey = rsa.Encrypt(aes.Key, RSAEncryptionPadding.OaepSHA256);

                // Combine encrypted data, IV, and encrypted key
                string encryptedDataBase64 = Convert.ToBase64String(encryptedData);
                string ivBase64 = Convert.ToBase64String(aes.IV);
                string encryptedKeyBase64 = Convert.ToBase64String(encryptedKey);

                return $"{encryptedDataBase64}{Delimiter}{ivBase64}{Delimiter}{encryptedKeyBase64}";
            }
        }
    }

    public string Decrypt(string encryptedPackage)
    {
        string[] parts = encryptedPackage.Split(new[] { Delimiter }, StringSplitOptions.None);
        if (parts.Length != 3)
        {
            throw new ArgumentException("Invalid encrypted package format");
        }

        byte[] encryptedData = Convert.FromBase64String(parts[0]);
        byte[] iv = Convert.FromBase64String(parts[1]);
        byte[] encryptedKey = Convert.FromBase64String(parts[2]);

        using (RSA rsa = _certificate.GetRSAPrivateKey())
        {
            // Decrypt AES key
            byte[] aesKey = rsa.Decrypt(encryptedKey, RSAEncryptionPadding.OaepSHA256);

            using (Aes aes = Aes.Create())
            {
                aes.Key = aesKey;
                aes.IV = iv;

                // Decrypt data
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(encryptedData, 0, encryptedData.Length);
                    }
                    return Encoding.UTF8.GetString(ms.ToArray());
                }
            }
        }
    }
}