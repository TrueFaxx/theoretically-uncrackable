using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace ImageWare.Enhanced;

public static class LicenseSignerEnhanced
{
    private static readonly JsonSerializerOptions JsonRead = new()
    {
        PropertyNameCaseInsensitive = true
    };

    private static readonly JsonSerializerOptions JsonWrite = new()
    {
        WriteIndented = true
    };

    // DEV SIDE: create a signed license.json with enhanced security
    public static string CreateSignedLicenseJson(
        string privateKeyPkcs8B64,
        string hardwareCode32,
        DateTime expiresUtc,
        string[] features,
        Dictionary<string, string>? fileHashes = null,
        bool enableIntegrity = true,
        int maxRunCount = -1) // -1 means unlimited
    {
        var payloadObj = new EnhancedLicensePayload
        {
            LicenseId = Guid.NewGuid().ToString("N"),
            IssuedUtc = DateTime.UtcNow,
            ExpiresUtc = expiresUtc.ToUniversalTime(),
            HwidHash = CryptoUtilEnhanced.Sha256Hex(hardwareCode32),
            Features = features ?? Array.Empty<string>(),
            FileHashes = fileHashes,
            EnableIntegrity = enableIntegrity,
            MaxRunCount = maxRunCount,
            CurrentRunCount = 0
        };

        var payloadJson = JsonSerializer.Serialize(payloadObj, JsonWrite);
        var payloadBytes = Encoding.UTF8.GetBytes(payloadJson);

        var sigBytes = Sign(privateKeyPkcs8B64, payloadBytes);

        var lic = new LicenseFile
        {
            Payload = CryptoUtilEnhanced.Base64UrlEncode(payloadBytes),
            Sig = CryptoUtilEnhanced.Base64UrlEncode(sigBytes),
            FormatVersion = 2 // Enhanced format
        };

        return JsonSerializer.Serialize(lic, JsonWrite);
    }

    // CLIENT SIDE: validate license.json with enhanced checks
    public static bool TryValidateLicense(
        string publicKeySpkiB64,
        string licenseJson,
        string localHardwareCode32,
        out EnhancedLicensePayload? payload,
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
            payloadBytes = CryptoUtilEnhanced.Base64UrlDecode(file.Payload);
            sigBytes = CryptoUtilEnhanced.Base64UrlDecode(file.Sig);
        }
        catch
        {
            error = "License payload/signature encoding is invalid.";
            return false;
        }

        // 1) signature verification
        if (!Verify(publicKeySpkiB64, payloadBytes, sigBytes))
        {
            error = "Invalid signature (license edited or not issued by you).";
            return false;
        }

        // 2) payload parse
        try
        {
            var payloadJson = Encoding.UTF8.GetString(payloadBytes);
            payload = JsonSerializer.Deserialize<EnhancedLicensePayload>(payloadJson, JsonRead);
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

        // 3) expiry check
        if (DateTime.UtcNow > payload.ExpiresUtc.ToUniversalTime())
        {
            error = "License expired.";
            return false;
        }

        // 4) hwid binding check
        var localHash = CryptoUtilEnhanced.Sha256Hex(localHardwareCode32);
        if (!CryptoUtilEnhanced.FixedTimeEqualsAscii(localHash, payload.HwidHash.Trim().ToLowerInvariant()))
        {
            error = "HWID mismatch (license not for this PC).";
            return false;
        }

        // 5) Virtual environment check
        if (HardwareCodeEnhanced.IsVirtualEnvironment())
        {
            error = "Running in virtual environment (license violation).";
            return false;
        }

        // 6) Debugger check
        if (HardwareCodeEnhanced.IsDebugged())
        {
            error = "Debugger detected (license violation).";
            return false;
        }

        // 7) Run count check (if limited)
        if (payload.MaxRunCount >= 0)
        {
            var runCount = LicenseStorageEnhanced.IncrementRunCount(payload.LicenseId);
            if (runCount > payload.MaxRunCount)
            {
                error = "Maximum run count exceeded.";
                return false;
            }
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

public sealed class LicenseFile
{
    [JsonPropertyName("payload")]
    public string Payload { get; set; } = "";

    [JsonPropertyName("sig")]
    public string Sig { get; set; } = "";

    [JsonPropertyName("formatVersion")]
    public int FormatVersion { get; set; } = 1;
}

public sealed class EnhancedLicensePayload
{
    [JsonPropertyName("licenseId")]
    public string LicenseId { get; set; } = "";

    [JsonPropertyName("issuedUtc")]
    public DateTime IssuedUtc { get; set; }

    [JsonPropertyName("expiresUtc")]
    public DateTime ExpiresUtc { get; set; }

    // sha256 hex of HardwareCode.Get(32)
    [JsonPropertyName("hwidHash")]
    public string HwidHash { get; set; } = "";

    [JsonPropertyName("features")]
    public string[] Features { get; set; } = Array.Empty<string>();

    // OPTIONAL: integrity list (filename -> sha256 hex)
    [JsonPropertyName("fileHashes")]
    public Dictionary<string, string>? FileHashes { get; set; }
    
    [JsonPropertyName("enableIntegrity")]
    public bool EnableIntegrity { get; set; } = true;
    
    [JsonPropertyName("maxRunCount")]
    public int MaxRunCount { get; set; } = -1; // -1 = unlimited
    
    [JsonPropertyName("currentRunCount")]
    public int CurrentRunCount { get; set; } = 0;
}