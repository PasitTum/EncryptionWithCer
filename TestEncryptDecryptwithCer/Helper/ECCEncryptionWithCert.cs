using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

public class ECCEncryptionWithCert
{
    private readonly X509Certificate2 _certificate;
    private const string Delimiter = "::"; // ใช้แยก encrypted data และ encrypted key

    public ECCEncryptionWithCert(string thumbprint)
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
        using (ECDsa ecdsa = _certificate.GetECDsaPublicKey())
        {
            return Convert.ToBase64String(ecdsa.ExportSubjectPublicKeyInfo());
        }
    }

    public string Encrypt(string data)
    {
        using (ECDsa ecdsa = _certificate.GetECDsaPublicKey())
        {
            ECParameters publicKeyParams = ecdsa.ExportParameters(false);
            using (ECDiffieHellman ecdhSender = ECDiffieHellman.Create(publicKeyParams.Curve))
            {
                byte[] senderPublicKey = ecdhSender.PublicKey.ToByteArray();

                // Use the certificate's public key to derive the shared secret
                ECDiffieHellman tempEcdh = ECDiffieHellman.Create(publicKeyParams.Curve);
                tempEcdh.ImportParameters(publicKeyParams);
                byte[] sharedSecret = ecdhSender.DeriveKeyMaterial(tempEcdh.PublicKey);

                using (var aes = new AesManaged())
                {
                    aes.Key = sharedSecret;
                    aes.GenerateIV();

                    using (var encryptor = aes.CreateEncryptor())
                    {
                        byte[] plainTextBytes = Encoding.UTF8.GetBytes(data);
                        byte[] cipherTextBytes = encryptor.TransformFinalBlock(plainTextBytes, 0, plainTextBytes.Length);

                        string encryptedDataBase64 = Convert.ToBase64String(cipherTextBytes);
                        string ivBase64 = Convert.ToBase64String(aes.IV);
                        string senderPublicKeyBase64 = Convert.ToBase64String(senderPublicKey);

                        return $"{encryptedDataBase64}::{ivBase64}::{senderPublicKeyBase64}";
                    }
                }
            }
        }
    }

    public string Decrypt(string encryptedPackage)
    {
        string[] parts = encryptedPackage.Split(new[] { "::" }, StringSplitOptions.None);
        if (parts.Length != 3)
        {
            throw new ArgumentException("Invalid encrypted package format");
        }

        byte[] encryptedData = Convert.FromBase64String(parts[0]);
        byte[] iv = Convert.FromBase64String(parts[1]);
        byte[] senderPublicKeyBytes = Convert.FromBase64String(parts[2]);

        using (ECDsa ecdsaReceiver = _certificate.GetECDsaPrivateKey())
        {
            ECParameters receiverParams = ecdsaReceiver.ExportParameters(true);
            using (ECDiffieHellman ecdhReceiver = ECDiffieHellman.Create(receiverParams))
            {
                // Import sender's public key
                ECDiffieHellman tempEcdh = ECDiffieHellman.Create(ecdhReceiver.ExportParameters(false).Curve);
                tempEcdh.ImportSubjectPublicKeyInfo(senderPublicKeyBytes, out _);
                ECDiffieHellmanPublicKey senderPublicKey = tempEcdh.PublicKey;

                byte[] sharedSecret = ecdhReceiver.DeriveKeyMaterial(senderPublicKey);

                using (var aes = new AesManaged())
                {
                    aes.Key = sharedSecret;
                    aes.IV = iv;

                    using (var decryptor = aes.CreateDecryptor())
                    {
                        byte[] decryptedBytes = decryptor.TransformFinalBlock(encryptedData, 0, encryptedData.Length);
                        return Encoding.UTF8.GetString(decryptedBytes);
                    }
                }
            }
        }
    }
}