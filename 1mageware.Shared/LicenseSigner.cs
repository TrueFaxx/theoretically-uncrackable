using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace ImageWare.Shared;

public static class LicenseSigner
{
    private static readonly JsonSerializerOptions JsonRead = new()
    {
        PropertyNameCaseInsensitive = true
    };

    private static readonly JsonSerializerOptions JsonWrite = new()
    {
        WriteIndented = true
    };

    // DEV SIDE: create a signed license.json
    public static string CreateSignedLicenseJson(
        string privateKeyPkcs8B64,
        string hardwareCode24,
        DateTime expiresUtc,
        string[] features,
        Dictionary<string, string>? fileHashes = null)
    {
        var payloadObj = new LicensePayload
        {
            LicenseId = Guid.NewGuid().ToString("N"),
            IssuedUtc = DateTime.UtcNow,
            ExpiresUtc = expiresUtc.ToUniversalTime(),
            HwidHash = CryptoUtil.Sha256Hex(hardwareCode24),
            Features = features ?? Array.Empty<string>(),
            FileHashes = fileHashes
        };

        var payloadJson = JsonSerializer.Serialize(payloadObj, JsonWrite);
        var payloadBytes = Encoding.UTF8.GetBytes(payloadJson);

        var sigBytes = Sign(privateKeyPkcs8B64, payloadBytes);

        var lic = new LicenseFile
        {
            Payload = CryptoUtil.Base64UrlEncode(payloadBytes),
            Sig = CryptoUtil.Base64UrlEncode(sigBytes)
        };

        return JsonSerializer.Serialize(lic, JsonWrite);
    }

    // CLIENT SIDE: validate license.json
    public static bool TryValidateLicense(
        string publicKeySpkiB64,
        string licenseJson,
        string localHardwareCode24,
        out LicensePayload? payload,
        out string error)
    {
        payload = null;
        error = "";

        LicenseFile? file;
        try
        {
            file = JsonSerializer.Deserialize<LicenseFile>(licenseJson, JsonRead);
            if (file is null || string.IsNullOrWhiteSpace(file.Payload) || string.IsNullOrWhiteSpace(file.Sig))
            {
                error = "License file missing payload/signature.";
                return false;
            }
        }
        catch
        {
            error = "License file JSON is invalid.";
            return false;
        }

        byte[] payloadBytes, sigBytes;
        try
        {
            payloadBytes = CryptoUtil.Base64UrlDecode(file.Payload);
            sigBytes = CryptoUtil.Base64UrlDecode(file.Sig);
        }
        catch
        {
            error = "License payload/signature encoding is invalid.";
            return false;
        }

        // 1) signature
        if (!Verify(publicKeySpkiB64, payloadBytes, sigBytes))
        {
            error = "Invalid signature (license edited or not issued by you).";
            return false;
        }

        // 2) payload parse
        try
        {
            var payloadJson = Encoding.UTF8.GetString(payloadBytes);
            payload = JsonSerializer.Deserialize<LicensePayload>(payloadJson, JsonRead);
            if (payload is null)
            {
                error = "License payload is invalid.";
                return false;
            }
        }
        catch
        {
            error = "License payload JSON is invalid.";
            return false;
        }

        // 3) expiry
        if (DateTime.UtcNow > payload.ExpiresUtc.ToUniversalTime())
        {
            error = "License expired.";
            return false;
        }

        // 4) hwid bind
        var localHash = CryptoUtil.Sha256Hex(localHardwareCode24);
        if (!CryptoUtil.FixedTimeEqualsAscii(localHash, payload.HwidHash.Trim().ToLowerInvariant()))
        {
            error = "HWID mismatch (license not for this PC).";
            return false;
        }

        return true;
    }

    private static byte[] Sign(string privateKeyPkcs8B64, byte[] payloadBytes)
    {
        using var ecdsa = ECDsa.Create();
        var priv = Convert.FromBase64String(privateKeyPkcs8B64);
        ecdsa.ImportPkcs8PrivateKey(priv, out _);
        return ecdsa.SignData(payloadBytes, HashAlgorithmName.SHA256);
    }

    private static bool Verify(string publicKeySpkiB64, byte[] payloadBytes, byte[] sigBytes)
    {
        using var ecdsa = ECDsa.Create();
        var pub = Convert.FromBase64String(publicKeySpkiB64);
        ecdsa.ImportSubjectPublicKeyInfo(pub, out _);
        return ecdsa.VerifyData(payloadBytes, sigBytes, HashAlgorithmName.SHA256);
    }
}
