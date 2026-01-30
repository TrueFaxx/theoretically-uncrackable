using System.Security.Cryptography;
using System.Text;

namespace ImageWare.Shared;

public static class CryptoUtil
{
    public static string Sha256Hex(string input)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(input));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    public static string Base64UrlEncode(byte[] bytes)
        => Convert.ToBase64String(bytes).Replace("+", "-").Replace("/", "_").TrimEnd('=');

    public static byte[] Base64UrlDecode(string s)
    {
        s = s.Replace("-", "+").Replace("_", "/");
        switch (s.Length % 4)
        {
            case 2: s += "=="; break;
            case 3: s += "="; break;
        }
        return Convert.FromBase64String(s);
    }

    public static bool FixedTimeEqualsAscii(string a, string b)
    {
        if (a.Length != b.Length) return false;
        var ba = Encoding.ASCII.GetBytes(a);
        var bb = Encoding.ASCII.GetBytes(b);
        return CryptographicOperations.FixedTimeEquals(ba, bb);
    }
}
