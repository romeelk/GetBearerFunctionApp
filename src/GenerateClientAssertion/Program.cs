using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;



internal class Program
{
    private static void Main(string[] args)
    {
   
        X509Certificate2 cert = new X509Certificate2("/Users/romeel.khan@contino.io/dev/GetBearerFunctionApp/scripts/testcert.pfx", "", X509KeyStorageFlags.Exportable);

        Console.WriteLine("Loaded cert");

        var assertion = GetSignedClientAssertion(cert, "0893480d-4a15-4aa8-b46b-75e6bf0a63f4", "6467738c-c2b4-4d76-ba04-073f885c72e0");
        Console.WriteLine(assertion);
        static string Base64UrlEncode(byte[] arg)
        {
            char Base64PadCharacter = '=';
            char Base64Character62 = '+';
            char Base64Character63 = '/';
            char Base64UrlCharacter62 = '-';
            char Base64UrlCharacter63 = '_';

            string s = Convert.ToBase64String(arg);
            s = s.Split(Base64PadCharacter)[0]; // RemoveAccount any trailing padding
            s = s.Replace(Base64Character62, Base64UrlCharacter62); // 62nd char of encoding
            s = s.Replace(Base64Character63, Base64UrlCharacter63); // 63rd char of encoding

            return s;
        }

        static string GetSignedClientAssertion(X509Certificate2 certificate, string tenantId, string clientId)
        {
            // Get the RSA with the private key, used for signing.
            var rsa = certificate.GetRSAPrivateKey();

            //alg represents the desired signing algorithm, which is SHA-256 in this case
            //x5t represents the certificate thumbprint base64 url encoded
            var header = new Dictionary<string, string>()
            {
                { "alg", "RS256"},
                { "typ", "JWT" },
                { "x5t", Base64UrlEncode(certificate.GetCertHash()) }
            };

            //Please see the previous code snippet on how to craft claims for the GetClaims() method
            var claims = GetClaims(tenantId, clientId);

            var headerBytes = JsonSerializer.SerializeToUtf8Bytes(header);
            var claimsBytes = JsonSerializer.SerializeToUtf8Bytes(claims);
            string token = Base64UrlEncode(headerBytes) + "." + Base64UrlEncode(claimsBytes);

            string signature = Base64UrlEncode(rsa.SignData(Encoding.UTF8.GetBytes(token), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
            string signedClientAssertion = string.Concat(token, ".", signature);
            return signedClientAssertion;
        }
        static IDictionary<string, object> GetClaims(string tenantId, string clientId)
        {
            //aud = https://login.microsoftonline.com/ + Tenant ID + /v2.0
            string aud = $"https://login.microsoftonline.com/{tenantId}/oauth2/token";

            string ConfidentialClientID = clientId; //client id 00000000-0000-0000-0000-000000000000
            const uint JwtToAadLifetimeInSeconds = 60 * 10; // Ten minutes
            DateTimeOffset validFrom = DateTimeOffset.UtcNow;
            DateTimeOffset validUntil = validFrom.AddSeconds(JwtToAadLifetimeInSeconds);

            return new Dictionary<string, object>()
            {
                { "aud", aud },
                { "exp", validUntil.ToUnixTimeSeconds() },
                { "iss", ConfidentialClientID },
                { "jti", Guid.NewGuid().ToString() },
                { "nbf", validFrom.ToUnixTimeSeconds() },
                { "sub", ConfidentialClientID }
            };
        }
    }
}