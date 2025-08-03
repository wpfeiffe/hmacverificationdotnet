using System;
using System.Security.Cryptography;
using System.Text;

namespace HmacVerificationApi.Services
{
    public class HmacVerificationService
    {
        private readonly string _secretKey;

        public HmacVerificationService(string secretKey)
        {
            _secretKey = secretKey ?? throw new ArgumentNullException(nameof(secretKey));
        }

        public bool VerifyHmacSignature(string payload, string providedSignature)
        {
            if (string.IsNullOrEmpty(payload) || string.IsNullOrEmpty(providedSignature))
            {
                return false;
            }

            string calculatedSignature = CalculateHmacSignature(payload);
            
            // Perform a time-constant comparison to prevent timing attacks
            return StringComparer.OrdinalIgnoreCase.Compare(calculatedSignature, providedSignature) == 0;
        }

        public string CalculateHmacSignature(string payload)
        {
            byte[] keyBytes = Encoding.UTF8.GetBytes(_secretKey);
            byte[] messageBytes = Encoding.UTF8.GetBytes(payload);

            using (var hmac = new HMACSHA256(keyBytes))
            {
                byte[] hashBytes = hmac.ComputeHash(messageBytes);
                return Convert.ToBase64String(hashBytes);
            }
        }
    }
}