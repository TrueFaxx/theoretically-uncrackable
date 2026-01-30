using System.Text.Json.Serialization;

namespace ImageWare.Shared;

public sealed class LicenseFile
{
    [JsonPropertyName("payload")]
    public string Payload { get; set; } = "";

    [JsonPropertyName("sig")]
    public string Sig { get; set; } = "";
}

public sealed class LicensePayload
{
    [JsonPropertyName("licenseId")]
    public string LicenseId { get; set; } = "";

    [JsonPropertyName("issuedUtc")]
    public DateTime IssuedUtc { get; set; }

    [JsonPropertyName("expiresUtc")]
    public DateTime ExpiresUtc { get; set; }

    // sha256 hex of HardwareCode.Get(24)
    [JsonPropertyName("hwidHash")]
    public string HwidHash { get; set; } = "";

    [JsonPropertyName("features")]
    public string[] Features { get; set; } = Array.Empty<string>();

    // OPTIONAL: integrity list (filename -> sha256 hex)
    [JsonPropertyName("fileHashes")]
    public Dictionary<string, string>? FileHashes { get; set; }
}
