# สร้าง certificate


$cert = New-SelfSignedCertificate  -Subject "CN=EncryptionCert"  -CertStoreLocation "cert:\LocalMachine\My" -KeyUsage KeyEncipherment, DataEncipherment  -KeyAlgorithm RSA -KeyLength 1024  -NotAfter (Get-Date).AddYears(1000)








Win  + R certlm.msc เข้าไปดู Cert
