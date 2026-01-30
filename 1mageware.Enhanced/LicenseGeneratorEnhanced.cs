using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using ImageWare.Enhanced;

Console.WriteLine("=== 1mageWare Enhanced LicenseGen ===");

// Press Enter to auto-generate/load keys from AppData
Console.Write("PrivateKey (PKCS#8 Base64) [press Enter to auto-auto-generate/load]: ");
var privInput = (Console.ReadLine() ?? "").Trim();

var (privB64, pubB64) = EnsureKeys(privInput);

// Tell you exactly what to paste into the client
Console.WriteLine();
Console.WriteLine("PUBLIC KEY (SPKI Base64) - paste into Client Program.cs:");
Console.WriteLine(pubB64);
Console.WriteLine();

Console.Write("User Hardware Code (32 chars): ");
var hw = (Console.ReadLine() ?? "").Trim();
if (hw.Length != 32)
{
    Console.WriteLine("HW code must be exactly 32 chars (use enhanced hardware code generator).");
    return;
}

Console.Write("Expires UTC (e.g. 2026-12-31): ");
var expStr = (Console.ReadLine() ?? "").Trim();
if (!DateTime.TryParse(expStr, out var exp))
{
    Console.WriteLine("Bad date. Example: 2026-12-31");
    return;
}
var expiresUtc = DateTime.SpecifyKind(exp, DateTimeKind.Utc);

Console.Write("Features (comma separated, optional): ");
var featsStr = (Console.ReadLine() ?? "").Trim();
var features = string.IsNullOrWhiteSpace(featsStr)
    ? Array.Empty<string>()
    : featsStr.Split(',')
        .Select(x => x.Trim())
        .Where(x => x.Length > 0)
        .ToArray();

// OPTIONAL integrity hashes (enhanced mode): hash all exe/dlls in a folder
Console.Write("Add file integrity hashes? (y/n): ");
var doIntegrity = (Console.ReadLine() ?? "").Trim().Equals("y", StringComparison.OrdinalIgnoreCase);

// OPTION for run count limits
Console.Write("Max run count (-1 for unlimited): ");
var runCountStr = (Console.ReadLine() ?? "").Trim();
int maxRunCount = -1;
if (int.TryParse(runCountStr, out var parsedRunCount))
{
    maxRunCount = parsedRunCount;
}

Dictionary<string, string>? fileHashes = null;
if (doIntegrity)
{
    Console.Write("Release folder path (where your client exe/dlls are): ");
    var folder = (Console.ReadLine() ?? "").Trim();

    if (!Directory.Exists(folder))
    {
        Console.WriteLine("Folder not found.");
        return;
    }

    fileHashes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

    foreach (var file in Directory.GetFiles(folder, "*.*", SearchOption.AllDirectories))
    {
        var name = Path.GetFileName(file);

        // Include more file types for enhanced integrity checking
        if (name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ||
            name.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ||
            name.EndsWith(".so", StringComparison.OrdinalIgnoreCase) ||
            name.EndsWith(".dylib", StringComparison.OrdinalIgnoreCase))
        {
            fileHashes[GetRelativePath(file, folder)] = IntegrityEnhanced.Sha256FileHex(file);
        }
    }

    Console.WriteLine($"Hashed {fileHashes.Count} file(s).");
}

var licenseJson = LicenseSignerEnhanced.CreateSignedLicenseJson(
    privateKeyPkcs8B64: privB64,
    hardwareCode32: hw,
    expiresUtc: expiresUtc,
    features: features,
    fileHashes: fileHashes,
    enableIntegrity: doIntegrity,
    maxRunCount: maxRunCount
);

Console.WriteLine();
Console.WriteLine("=== ENHANCED LICENSE.JSON ===");
Console.WriteLine(licenseJson);
Console.WriteLine();
Console.WriteLine(@"Save it as: %LOCALAPPDATA%\1mageWare\secure_data\license.dat");

// ---------------- helpers ----------------

static (string privB64, string pubB64) EnsureKeys(string userProvidedPrivB64)
{
    var keysDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "1mageWare",
        "secure_keys"
    );
    Directory.CreateDirectory(keysDir);

    var privPath = Path.Combine(keysDir, "private_pkcs8.b64");
    var pubPath  = Path.Combine(keysDir, "public_spki.b64");

    // If user pasted a private key, use it and regenerate public key from it
    if (!string.IsNullOrWhiteSpace(userProvidedPrivB64))
    {
        var pub = DerivePublicFromPrivate(userProvidedPrivB64);

        File.WriteAllText(privPath, userProvidedPrivB64);
        File.WriteAllText(pubPath, pub);

        Console.WriteLine();
        Console.WriteLine("Loaded private key you provided and saved keys to:");
        Console.WriteLine(privPath);
        Console.WriteLine(pubPath);

        return (userProvidedPrivB64, pub);
    }

    // Load existing keys if present
    if (File.Exists(privPath) && File.Exists(pubPath))
    {
        var priv = File.ReadAllText(privPath).Trim();
        var pub = File.ReadAllText(pubPath).Trim();

        Console.WriteLine();
        Console.WriteLine("Loaded existing keys from:");
        Console.WriteLine(privPath);
        Console.WriteLine(pubPath);

        return (priv, pub);
    }

    // Generate new keys with stronger curve
    using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    var newPrivB64 = Convert.ToBase64String(ecdsa.ExportPkcs8PrivateKey());
    var newPubB64  = Convert.ToBase64String(ecdsa.ExportSubjectPublicKeyInfo());

    File.WriteAllText(privPath, newPrivB64);
    File.WriteAllText(pubPath, newPubB64);

    Console.WriteLine();
    Console.WriteLine("Generated NEW signing keys and saved to:");
    Console.WriteLine(privPath);
    Console.WriteLine(pubPath);
    Console.WriteLine("DO NOT ship the private key. Keep it dev-only.");

    return (newPrivB64, newPubB64);
}

static string DerivePublicFromPrivate(string privateKeyPkcs8B64)
{
    using var ecdsa = ECDsa.Create();
    ecdsa.ImportPkcs8PrivateKey(Convert.FromBase64String(privateKeyPkcs8B64), out _);
    return Convert.ToBase64String(ecdsa.ExportSubjectPublicKeyInfo());
}

static string GetRelativePath(string filePath, string basePath)
{
    var fileUri = new Uri(filePath);
    var baseUri = new Uri(basePath.EndsWith(Path.DirectorySeparatorChar.ToString()) 
        ? basePath 
        : basePath + Path.DirectorySeparatorChar);
    
    var relativeUri = baseUri.MakeRelativeUri(fileUri);
    return Uri.UnescapeDataString(relativeUri.ToString()).Replace('/', Path.DirectorySeparatorChar);
}