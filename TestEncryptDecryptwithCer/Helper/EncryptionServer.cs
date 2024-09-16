using System;
using System.Text;
using System.Text.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace TestEncryptDecryptwithCer.Helper
{
    public class EncryptionServer
    {
        private readonly string _thumbprint;

        public EncryptionServer(string thumbprint)
        {
            _thumbprint = thumbprint;
        }

        private X509Certificate2 GetCertificate()
        {
            using (X509Store store = new X509Store(StoreName.My, StoreLocation.LocalMachine))
            {
                store.Open(OpenFlags.ReadOnly);
                X509Certificate2Collection certs = store.Certificates.Find(X509FindType.FindBySubjectName, _thumbprint, false);
                if (certs.Count > 0)
                {
                    return certs[0];
                }
            }
            throw new Exception("Certificate not found");
        }

        public string Encrypt<T>(T data)
        {
            byte[] jsonBytes = ObjectToByteArray(data);
            X509Certificate2 cert = GetCertificate();
            using (RSA rsa = cert.GetRSAPublicKey())
            {
                byte[] encryptedData = rsa.Encrypt(jsonBytes, RSAEncryptionPadding.OaepSHA256);
                return Convert.ToBase64String(encryptedData);
            }
        }

        public T Decrypt<T>(string encryptedBase64)
        {
            byte[] encryptedData = Convert.FromBase64String(encryptedBase64);
            X509Certificate2 cert = GetCertificate();
            using (RSA rsa = cert.GetRSAPrivateKey())
            {
                byte[] decryptedData = rsa.Decrypt(encryptedData, RSAEncryptionPadding.OaepSHA256);
                return ByteArrayToObject<T>(decryptedData);
            }
        }

        private byte[] ObjectToByteArray(object obj)
        {
            string jsonString = JsonSerializer.Serialize(obj);
            return Encoding.UTF8.GetBytes(jsonString);
        }

        private T ByteArrayToObject<T>(byte[] arrBytes)
        {
            string jsonString = Encoding.UTF8.GetString(arrBytes);
            return JsonSerializer.Deserialize<T>(jsonString);
        }
    }
}