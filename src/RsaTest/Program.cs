using System;
using System.Security.Cryptography;
using System.Text;

namespace RsaTest
{
    internal class Program
    {
        private const string PublicKey = "<RSAKeyValue><Modulus>21wEnTU+mcD2w0Lfo1Gv4rtcSWsQJQTNa6gio05AOkV/Er9w3Y13Ddo5wGtjJ19402S71HUeN0vbKILLJdRSES5MHSdJPSVrOqdrll/vLXxDxWs/U0UT1c8u6k/Ogx9hTtZxYwoeYqdhDblof3E75d9n2F0Zvf6iTb4cI7j6fMs=</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";
        private const string PrivateKey = "<RSAKeyValue><Modulus>21wEnTU+mcD2w0Lfo1Gv4rtcSWsQJQTNa6gio05AOkV/Er9w3Y13Ddo5wGtjJ19402S71HUeN0vbKILLJdRSES5MHSdJPSVrOqdrll/vLXxDxWs/U0UT1c8u6k/Ogx9hTtZxYwoeYqdhDblof3E75d9n2F0Zvf6iTb4cI7j6fMs=</Modulus><Exponent>AQAB</Exponent><P>/aULPE6jd5IkwtWXmReyMUhmI/nfwfkQSyl7tsg2PKdpcxk4mpPZUdEQhHQLvE84w2DhTyYkPHCtq/mMKE3MHw==</P><Q>3WV46X9Arg2l9cxb67KVlNVXyCqc/w+LWt/tbhLJvV2xCF/0rWKPsBJ9MC6cquaqNPxWWEav8RAVbmmGrJt51Q==</Q><DP>8TuZFgBMpBoQcGUoS2goB4st6aVq1FcG0hVgHhUI0GMAfYFNPmbDV3cY2IBt8Oj/uYJYhyhlaj5YTqmGTYbATQ==</DP><DQ>FIoVbZQgrAUYIHWVEYi/187zFd7eMct/Yi7kGBImJStMATrluDAspGkStCWe4zwDDmdam1XzfKnBUzz3AYxrAQ==</DQ><InverseQ>QPU3Tmt8nznSgYZ+5jUo9E0SfjiTu435ihANiHqqjasaUNvOHKumqzuBZ8NRtkUhS6dsOEb8A2ODvy7KswUxyA==</InverseQ><D>cgoRoAUpSVfHMdYXW9nA3dfX75dIamZnwPtFHq80ttagbIe4ToYYCcyUz5NElhiNQSESgS5uCgNWqWXt5PnPu4XmCXx6utco1UVH8HGLahzbAnSy6Cj3iUIQ7Gj+9gQ7PkC434HTtHazmxVgIR5l56ZjoQ8yGNCPZnsdYEmhJWk=</D></RSAKeyValue>";
        private const int DwKeySize = 1024;

        private static void Main()
        {
            Console.Write("Enter text to encrypt:");
            var data = Console.ReadLine();
            var encryptedText = EncryptData(data);
            Console.WriteLine("Encrypted text:");
            Console.WriteLine(encryptedText);
            var decryptedText = DecryptData(encryptedText);
            Console.WriteLine("Decrypted text:");
            Console.WriteLine(decryptedText);
            Console.ReadKey();
        }

        private static string EncryptData(string data)
        {
            string encryptedData;
            using (var rsa = new RSACryptoServiceProvider(DwKeySize))
            {
                try
                {
                    var dataBytes = Encoding.UTF8.GetBytes(data);
                    rsa.FromXmlString(PublicKey);
                    var base64EncryptedData = rsa.Encrypt(dataBytes, true);
                    encryptedData = Convert.ToBase64String(base64EncryptedData);
                }
                finally
                {
                    rsa.PersistKeyInCsp = false;
                }
            }
            return encryptedData;
        }

        private static string DecryptData(string encryptedData)
        {
            string decryptedData;
            using (var rsa = new RSACryptoServiceProvider(DwKeySize))
            {
                rsa.FromXmlString(PrivateKey);                
                var resultBytes = Convert.FromBase64String(encryptedData);
                var decryptedBytes = rsa.Decrypt(resultBytes, true);
                decryptedData = Encoding.UTF8.GetString(decryptedBytes);                
            }
            return decryptedData;
        }       
    }
}