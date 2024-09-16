using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using TestEncryptDecryptwithCer.Helper;
using TestEncryptDecryptwithCer.NewFolder;

namespace TestEncryptDecryptwithCer.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class WeatherForecastController : ControllerBase
    {
        private readonly ILogger<WeatherForecastController> _logger;
        private readonly EncryptionServer _encryptionServer;
        private readonly ECCEncryptionWithCert _encryptionECC;
        private readonly RSAEncryptionAESKey _encryptionAESKey;
        private readonly EncryptionByKey _encryptionByKey;

        public WeatherForecastController(ILogger<WeatherForecastController> logger)
        {
            _logger = logger;
            _encryptionServer = new EncryptionServer("EncryptionCert");
            _encryptionECC = new ECCEncryptionWithCert("ECCCert");
            _encryptionAESKey = new RSAEncryptionAESKey("EncryptionCert222");
            _encryptionByKey = new EncryptionByKey("EncryptionCert");
        }

        [HttpPost("CertEncryption")]
        public IActionResult CertEncryption(GetWeatherReq req)
        {
            // String
            string originalString = req.test ?? "ทดสอบ 12343";
            string encryptedString = _encryptionServer.Encrypt(originalString);
            string decryptedString = _encryptionServer.Decrypt<string>(encryptedString);

            // Integer
            int originalInt = 12345;
            string encryptedInt = _encryptionServer.Encrypt(originalInt);
            int decryptedInt = _encryptionServer.Decrypt<int>(encryptedInt);

            // Double
            double originalDouble = 123.45;
            string encryptedDouble = _encryptionServer.Encrypt(originalDouble);
            double decryptedDouble = _encryptionServer.Decrypt<double>(encryptedDouble);

            // Float
            float originalFloat = 123.45f;
            string encryptedFloat = _encryptionServer.Encrypt(originalFloat);
            float decryptedFloat = _encryptionServer.Decrypt<float>(encryptedFloat);

            // Boolean
            bool originalBool = true;
            string encryptedBool = _encryptionServer.Encrypt(originalBool);
            bool decryptedBool = _encryptionServer.Decrypt<bool>(encryptedBool);

            // Object
            var person = new Person { Name = "John Doe", Age = 30 };
            string encryptedPerson = _encryptionServer.Encrypt(person);
            var decryptedPerson = _encryptionServer.Decrypt<Person>(encryptedPerson);

            var response = new
            {
                String = new { Original = originalString, Encrypted = encryptedString, Decrypted = decryptedString },
                Integer = new { Original = originalInt, Encrypted = encryptedInt, Decrypted = decryptedInt },
                Double = new { Original = originalDouble, Encrypted = encryptedDouble, Decrypted = decryptedDouble },
                Float = new { Original = originalFloat, Encrypted = encryptedFloat, Decrypted = decryptedFloat },
                Boolean = new { Original = originalBool, Encrypted = encryptedBool, Decrypted = decryptedBool },
                Object = new { Original = person, Encrypted = encryptedPerson, Decrypted = decryptedPerson }
            };

            return Ok(response);
        }

        [HttpPost("EncryptECC")]
        public IActionResult EncryptECC(GetWeatherReq req)
        {
            // EEC ลองแล้ว เกิดปัญหาตอน Decrypt รูปแบบการ Encryption จะต้องไป Gen Curve ใหม่ทุกครั้ง ทำให้มีปัญหาตอน Decrypt (ไม่ได้ใช้แค่ Key ในการเข้ารหัส แต่เหมือนจะต้อง Gen วิธีการแกะรหัสเก็บไว้ด้วย )
            // String 
            string originalString = req.test ?? "ทดสอบ 12343";
            string encryptedString = _encryptionECC.Encrypt(originalString);
            string decryptedString = _encryptionECC.Decrypt(encryptedString);

            // Integer
            int originalInt = 12345;
            string encryptedInt = _encryptionECC.Encrypt(originalInt.ToString());
            int decryptedInt = int.Parse(_encryptionECC.Decrypt(encryptedInt));

            // Double
            double originalDouble = 123.45;
            string encryptedDouble = _encryptionECC.Encrypt(originalDouble.ToString());
            double decryptedDouble = double.Parse(_encryptionECC.Decrypt(encryptedDouble));

            // Float
            float originalFloat = 123.45f;
            string encryptedFloat = _encryptionECC.Encrypt(originalFloat.ToString());
            float decryptedFloat = float.Parse(_encryptionECC.Decrypt(encryptedFloat));

            // Boolean
            bool originalBool = true;
            string encryptedBool = _encryptionECC.Encrypt(originalBool.ToString());
            bool decryptedBool = bool.Parse(_encryptionECC.Decrypt(encryptedBool));
                
            // Object
            var person = new Person { Name = "John Doe", Age = 30 };
            string encryptedPerson = _encryptionECC.Encrypt(JsonSerializer.Serialize(person));
            var decryptedPerson = JsonSerializer.Deserialize<Person>(_encryptionECC.Decrypt(encryptedPerson));

            var response = new
            {
                String = new { Original = originalString, Encrypted = encryptedString, Decrypted = decryptedString },
                Integer = new { Original = originalInt, Encrypted = encryptedInt, Decrypted = decryptedInt },
                Double = new { Original = originalDouble, Encrypted = encryptedDouble, Decrypted = decryptedDouble },
                Float = new { Original = originalFloat, Encrypted = encryptedFloat, Decrypted = decryptedFloat },
                Boolean = new { Original = originalBool, Encrypted = encryptedBool, Decrypted = decryptedBool },
                Object = new { Original = person, Encrypted = encryptedPerson, Decrypted = decryptedPerson }
            };

            return Ok(response);
        }

        [HttpPost("RSAEncryptionAESKey")]
        public IActionResult RSAEncryptionAESKey(GetWeatherReq req)
        {
            // String
            string originalString = req.test ?? "ทดสอบ 12343";
            string encryptedString = _encryptionAESKey.Encrypt(originalString);
            string decryptedString = _encryptionAESKey.Decrypt<string>(encryptedString);

            // Integer
            int originalInt = 12345;
            string encryptedInt = _encryptionAESKey.Encrypt(originalInt);
            int decryptedInt = _encryptionAESKey.Decrypt<int>(encryptedInt);
              
            // Double
            double originalDouble = 123.45;
            string encryptedDouble = _encryptionAESKey.Encrypt(originalDouble);
            double decryptedDouble = _encryptionAESKey.Decrypt<double>(encryptedDouble);

            // Float
            float originalFloat = 123.45f;
            string encryptedFloat = _encryptionAESKey.Encrypt(originalFloat);
            float decryptedFloat = _encryptionAESKey.Decrypt<float>(encryptedFloat);

            // Boolean
            bool originalBool = true;
            string encryptedBool = _encryptionAESKey.Encrypt(originalBool);
            bool decryptedBool = _encryptionAESKey.Decrypt<bool>(encryptedBool);

            // Object
            var person = new Person { Name = "John Doe", Age = 30 };
            string encryptedPerson = _encryptionAESKey.Encrypt(person);
            var decryptedPerson = _encryptionAESKey.Decrypt<Person>(encryptedPerson);

            var response = new
            {
                String = new { Original = originalString, Encrypted = encryptedString, Decrypted = decryptedString },
                Integer = new { Original = originalInt, Encrypted = encryptedInt, Decrypted = decryptedInt },
                Double = new { Original = originalDouble, Encrypted = encryptedDouble, Decrypted = decryptedDouble },
                Float = new { Original = originalFloat, Encrypted = encryptedFloat, Decrypted = decryptedFloat },
                Boolean = new { Original = originalBool, Encrypted = encryptedBool, Decrypted = decryptedBool },
                Object = new { Original = person, Encrypted = encryptedPerson, Decrypted = decryptedPerson }
            };

            return Ok(response);
        }

        //[HttpPost("EncryptionByKey")]
        //public IActionResult EncryptionByKey(GetWeatherReq req)
        //{
        //    // String
        //    string originalString = req.test ?? "ทดสอบ 12343";
        //    string encryptedString = _encryptionByKey.Encrypt(originalString);
        //    string decryptedString = _encryptionByKey.Decrypt(encryptedString);

        //    // Integer
        //    int originalInt = 12345;
        //    string encryptedInt = _encryptionByKey.Encrypt(originalInt);
        //    int decryptedInt = _encryptionByKey.Decrypt(encryptedInt);

        //    // Double
        //    double originalDouble = 123.45;
        //    string encryptedDouble = _encryptionByKey.Encrypt(originalDouble);
        //    double decryptedDouble = _encryptionByKey.Decrypt<double>(encryptedDouble);

        //    // Float
        //    float originalFloat = 123.45f;
        //    string encryptedFloat = _encryptionAESKey.Encrypt(originalFloat);
        //    float decryptedFloat = _encryptionAESKey.Decrypt<float>(encryptedFloat);

        //    // Boolean
        //    bool originalBool = true;
        //    string encryptedBool = _encryptionAESKey.Encrypt(originalBool);
        //    bool decryptedBool = _encryptionAESKey.Decrypt<bool>(encryptedBool);

        //    // Object
        //    var person = new Person { Name = "John Doe", Age = 30 };
        //    string encryptedPerson = _encryptionAESKey.Encrypt(person);
        //    var decryptedPerson = _encryptionAESKey.Decrypt<Person>(encryptedPerson);

        //    var response = new
        //    {
        //        String = new { Original = originalString, Encrypted = encryptedString, Decrypted = decryptedString },
        //        Integer = new { Original = originalInt, Encrypted = encryptedInt, Decrypted = decryptedInt },
        //        Double = new { Original = originalDouble, Encrypted = encryptedDouble, Decrypted = decryptedDouble },
        //        Float = new { Original = originalFloat, Encrypted = encryptedFloat, Decrypted = decryptedFloat },
        //        Boolean = new { Original = originalBool, Encrypted = encryptedBool, Decrypted = decryptedBool },
        //        Object = new { Original = person, Encrypted = encryptedPerson, Decrypted = decryptedPerson }
        //    };

        //    return Ok(response);
        //}


        [HttpGet("publickey")]
        public IActionResult GetPublicKey()
        {
            return Ok(_encryptionAESKey.GetPublicKey());
        }

        [HttpPost("GetEncryptedData")]
        public IActionResult GetEncryptedData([FromBody] ClientPublicKeyModel model)
        {
            try
            {
                // แปลง public key จาก Base64 string เป็น RSA key
                byte[] publicKeyBytes = Convert.FromBase64String(model.PublicKey);
                using (RSA rsa = RSA.Create())
                {
                    rsa.ImportSubjectPublicKeyInfo(publicKeyBytes, out _);

                    // ข้อมูลที่ต้องการส่งกลับ
                    string sensitiveData = "This is sensitive data from the server";

                    // เข้ารหัสข้อมูลด้วย public key ของ client
                    byte[] encryptedData = rsa.Encrypt(Encoding.UTF8.GetBytes(sensitiveData), RSAEncryptionPadding.OaepSHA256);

                    // ส่งข้อมูลที่เข้ารหัสแล้วกลับไป
                    return Ok(Convert.ToBase64String(encryptedData));
                }
            }
            catch (Exception ex)
            {
                return BadRequest($"Error: {ex.Message}");
            }
        }
    }

}