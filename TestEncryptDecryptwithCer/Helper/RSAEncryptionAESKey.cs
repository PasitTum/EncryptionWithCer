using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

public class RSAEncryptionAESKey
{
    private readonly X509Certificate2 _certificate;
    private const string Delimiter = "::";

    public RSAEncryptionAESKey(string thumbprint)
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

    public string GetPublicKey()
    {
        byte[] key = _certificate.GetPublicKey();
        return Convert.ToBase64String(key);
        
    }

    public string Encrypt<T>(T data)
    {
        string jsonData = JsonSerializer.Serialize(data);
        using (RSA rsa = _certificate.GetRSAPublicKey())
        using (Aes aes = Aes.Create())
        {
            aes.GenerateKey();
            byte[] iv = aes.IV;

            // Encrypt the data with AES
            byte[] encryptedData;
            using (var encryptor = aes.CreateEncryptor())
            {
                byte[] dataBytes = Encoding.UTF8.GetBytes(jsonData);
                encryptedData = encryptor.TransformFinalBlock(dataBytes, 0, dataBytes.Length);
            }

            // Encrypt the AES key with RSA
            byte[] encryptedKey = rsa.Encrypt(aes.Key, RSAEncryptionPadding.OaepSHA256);

            string encryptedDataBase64 = Convert.ToBase64String(encryptedData);
            string ivBase64 = Convert.ToBase64String(iv);
            string encryptedKeyBase64 = Convert.ToBase64String(encryptedKey);

            return $"{encryptedDataBase64}{Delimiter}{ivBase64}{Delimiter}{encryptedKeyBase64}";
        }
    }

    public T Decrypt<T>(string encryptedPackage)
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
        using (Aes aes = Aes.Create())
        {
            // Decrypt the AES key
            byte[] key = rsa.Decrypt(encryptedKey, RSAEncryptionPadding.OaepSHA256);
            aes.Key = key;
            aes.IV = iv;

            // Decrypt the data
            using (var decryptor = aes.CreateDecryptor())
            {
                byte[] decryptedBytes = decryptor.TransformFinalBlock(encryptedData, 0, encryptedData.Length);
                string decryptedJson = Encoding.UTF8.GetString(decryptedBytes);
                return JsonSerializer.Deserialize<T>(decryptedJson);
            }
        }
    }
}