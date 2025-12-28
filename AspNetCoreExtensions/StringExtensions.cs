using System.Text;

namespace AspNetCoreExtensions;

public static class StringExtensions
{
    extension(string input)
    {
        public string ToBase64()
        {
            var plainTextBytes = Encoding.UTF8.GetBytes(input);
            return Convert.ToBase64String(plainTextBytes);
        }

        public string FromBase64()
        {
            var base64EncodedBytes = Convert.FromBase64String(input);
            return Encoding.UTF8.GetString(base64EncodedBytes);
        }
    }
}