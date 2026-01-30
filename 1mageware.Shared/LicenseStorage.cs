namespace ImageWare.Shared;

public static class LicenseStorage
{
    public static string GetAppDir()
    {
        var dir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "1mageWare"
        );
        Directory.CreateDirectory(dir);
        return dir;
    }

    public static string GetLicensePath()
        => Path.Combine(GetAppDir(), "license.json");

    public static string? TryReadLicense()
    {
        var path = GetLicensePath();
        return File.Exists(path) ? File.ReadAllText(path) : null;
    }

    public static void SaveLicense(string licenseJson)
    {
        File.WriteAllText(GetLicensePath(), licenseJson);
    }
}
