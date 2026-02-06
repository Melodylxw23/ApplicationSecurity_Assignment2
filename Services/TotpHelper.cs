using System;
using System.Security.Cryptography;
using System.Text;

namespace Assignment2.Services
{
    // Minimal Base32 and TOTP implementation (no external packages)
    public static class TotpHelper
    {
        private const string Base32Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

        public static string GenerateSecretBase32(int bytes = 20)
        {
            var data = new byte[bytes];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(data);
            return ToBase32(data);
        }

        public static string ToBase32(byte[] data)
        {
            if (data == null || data.Length == 0) return string.Empty;
            var sb = new StringBuilder();
            int buffer = data[0];
            int next = 1;
            int bitsLeft = 8;
            while (bitsLeft > 0 || next < data.Length)
            {
                if (bitsLeft < 5)
                {
                    if (next < data.Length)
                    {
                        buffer <<= 8;
                        buffer |= data[next++] & 0xff;
                        bitsLeft += 8;
                    }
                    else
                    {
                        int pad = 5 - bitsLeft;
                        buffer <<= pad;
                        bitsLeft += pad;
                    }
                }

                int index = (buffer >> (bitsLeft - 5)) & 0x1f;
                bitsLeft -= 5;
                sb.Append(Base32Chars[index]);
            }

            return sb.ToString();
        }

        public static byte[] FromBase32(string base32)
        {
            if (string.IsNullOrEmpty(base32)) return Array.Empty<byte>();
            base32 = base32.TrimEnd('=', '\r', '\n').ToUpperInvariant();
            int byteCount = base32.Length * 5 / 8;
            var result = new byte[byteCount];

            int buffer = 0;
            int bitsLeft = 0;
            int index = 0;
            foreach (var c in base32)
            {
                int val = Base32Chars.IndexOf(c);
                if (val < 0) continue;
                buffer <<= 5;
                buffer |= val & 0x1f;
                bitsLeft += 5;
                if (bitsLeft >= 8)
                {
                    result[index++] = (byte)((buffer >> (bitsLeft - 8)) & 0xff);
                    bitsLeft -= 8;
                }
            }

            return result;
        }

        // Compute TOTP code for a given timestep
        private static string ComputeTotp(byte[] secret, long timestep)
        {
            var timestepBytes = BitConverter.GetBytes(timestep);
            if (BitConverter.IsLittleEndian) Array.Reverse(timestepBytes);
            using var hmac = new HMACSHA1(secret);
            var hash = hmac.ComputeHash(timestepBytes);
            int offset = hash[hash.Length - 1] & 0x0f;
            int binaryCode = ((hash[offset] & 0x7f) << 24)
                             | ((hash[offset + 1] & 0xff) << 16)
                             | ((hash[offset + 2] & 0xff) << 8)
                             | (hash[offset + 3] & 0xff);
            int otp = binaryCode % 1000000;
            return otp.ToString("D6");
        }

        // Verify code allowing a window of steps for clock skew
        public static bool VerifyCode(string base32Secret, string code, int stepSeconds = 30, int window = 1)
        {
            if (string.IsNullOrWhiteSpace(base32Secret) || string.IsNullOrWhiteSpace(code)) return false;
            var secret = FromBase32(base32Secret);
            var unixTime = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var timestep = unixTime / stepSeconds;

            for (long i = -window; i <= window; i++)
            {
                var t = timestep + i;
                var generated = ComputeTotp(secret, t);
                if (string.Equals(generated, code, StringComparison.OrdinalIgnoreCase)) return true;
            }

            return false;
        }
    }
}
