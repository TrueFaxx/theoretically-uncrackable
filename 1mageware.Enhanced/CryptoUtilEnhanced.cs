using System;
using System.Security.Cryptography;
using System.Text;

namespace ImageWare.Enhanced;

public static class CryptoUtilEnhanced
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
    
    // Enhanced encryption wrapper for additional protection
    public static byte[] EncryptWithKey(byte[] data, byte[] key)
    {
        using var aes = Aes.Create();
        aes.Key = key[..aes.KeySize / 8]; // Use first N bytes based on key size
        aes.GenerateIV();
        
        using var encryptor = aes.CreateEncryptor();
        var encrypted = encryptor.TransformFinalBlock(data, 0, data.Length);
        
        // Prepend IV to encrypted data
        var result = new byte[aes.IV.Length + encrypted.Length];
        Array.Copy(aes.IV, 0, result, 0, aes.IV.Length);
        Array.Copy(encrypted, 0, result, aes.IV.Length, encrypted.Length);
        
        return result;
    }
    
    public static byte[] DecryptWithKey(byte[] encryptedData, byte[] key)
    {
        using var aes = Aes.Create();
        aes.Key = key[..aes.KeySize / 8];
        
        // Extract IV from beginning
        var iv = new byte[aes.IV.Length];
        Array.Copy(encryptedData, 0, iv, 0, iv.Length);
        aes.IV = iv;
        
        var data = new byte[encryptedData.Length - iv.Length];
        Array.Copy(encryptedData, iv.Length, data, 0, data.Length);
        
        using var decryptor = aes.CreateDecryptor();
        return decryptor.TransformFinalBlock(data, 0, data.Length);
    }
}