using System.Security.Cryptography;

namespace ImageWare.Shared;

public static class Integrity
{
    public static string Sha256FileHex(string path)
    {
        using var stream = File.OpenRead(path);
        using var sha = SHA256.Create();
        var hash = sha.ComputeHash(stream);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    // Compares expected hashes (relative file names) against current install dir.
    public static bool VerifyFileHashes(
        IReadOnlyDictionary<string, string> expected,
        string baseDir,
        out string error)
    {
        error = "";

        foreach (var kv in expected)
        {
            var rel = kv.Key.Replace('/', Path.DirectorySeparatorChar);
            var expectedHex = kv.Value.Trim().ToLowerInvariant();

            var full = Path.Combine(baseDir, rel);
            if (!File.Exists(full))
            {
                error = $"Missing file: {rel}";
                return false;
            }

            var actualHex = Sha256FileHex(full);
            if (!CryptoUtil.FixedTimeEqualsAscii(actualHex, expectedHex))
            {
                error = $"File modified: {rel}";
                return false;
            }
        }

        return true;
    }
}
