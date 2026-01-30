using ImageWare.Shared;

const string PublicKeySpkiB64 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEGKpvGydWaygAvJ3qW+03oGLNv11y+rjFzP+8A6j6VcL9pA8+f68WcA53j/JYMFvP5zhvk4hGct+nyOgMlnaynw==";

var hw = HardwareCode.Get(24);

var licensJson = LicenseStorage.TryReadLicense();
if (licensJson is null)
{
    Console.WriteLine("No license found.");
    Console.WriteLine("Hardware Code (send to dev): " + hw);
    return;
}

if (!LicenseSigner.TryValidateLicense(PublicKeySpkiB64, licensJson, hw, out var payload, out var err))
{
    Console.WriteLine("License invalid: " + err);
    Console.WriteLine("Hardware Code: " + hw);
    return;
}

// stuff for optional file integrity check (only if license includes fileHashes)
if (payload!.FileHashes is { Count: > 0 })
{
    var baseDir = AppContext.BaseDirectory; // folder where exe lives
    if (!Integrity.VerifyFileHashes(payload.FileHashes, baseDir, out var iErr))
    {
        Console.WriteLine("Integrity fail: " + iErr);
        return;
    }
}

Console.WriteLine("License OK: " + payload.LicenseId);
Console.WriteLine("Expires: " + payload.ExpiresUtc.ToUniversalTime().ToString("u"));
Console.WriteLine("Features: " + string.Join(", ", payload.Features));

// TODO: run your protected software here
Console.WriteLine("Running app...");
