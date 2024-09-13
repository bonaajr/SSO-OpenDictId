using System.Security.Cryptography;
using System.Text;

namespace api_sso.Api.Helpers
{
    public static class PasswordHelper
    {
        public static string HashMD5String(string input)
        {
            byte[] inputBytes = Encoding.UTF8.GetBytes(input);

            using MD5 md5 = MD5.Create();

            byte[] hashBytes = md5.ComputeHash(inputBytes);

            StringBuilder sb = new();
            for (int i = 0; i < hashBytes.Length; i++)
            {
                sb.Append(hashBytes[i].ToString("x2"));
            }
            return sb.ToString().ToUpper();
        }
    }
}