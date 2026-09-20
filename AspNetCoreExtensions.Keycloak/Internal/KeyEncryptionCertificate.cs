using System.Security.Cryptography.X509Certificates;
using AspNetCoreExtensions.Keycloak.Options;

namespace AspNetCoreExtensions.Keycloak.Internal;

internal static class KeyEncryptionCertificate
{
    /// <summary>Load the certificate the data protection key ring is encrypted with.</summary>
    /// <remarks>
    /// Called during service registration, so a bad certificate fails at startup.
    /// </remarks>
    internal static X509Certificate2 Load(ValkeyOptions options)
    {
        ThrowIfBlank(options.KeyEncryptionCertificatePath, nameof(ValkeyOptions.KeyEncryptionCertificatePath));
        ThrowIfBlank(options.KeyEncryptionPrivateKeyPath, nameof(ValkeyOptions.KeyEncryptionPrivateKeyPath));

        var certificate = X509Certificate2.CreateFromPemFile(options.KeyEncryptionCertificatePath,
            options.KeyEncryptionPrivateKeyPath);

        // an EC certificate loads happily and then fails on first use, when the key ring is already unreadable
        if (certificate.GetRSAPrivateKey() is not null)
        {
            return certificate;
        }

        certificate.Dispose();

        throw new InvalidOperationException(
            $"The certificate at '{options.KeyEncryptionCertificatePath}' has no RSA private key.");
    }

    private static void ThrowIfBlank(string path, string name)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new InvalidOperationException(
                $"{nameof(ValkeyOptions)}.{name} is required. The data protection key ring is encrypted at rest, which needs an RSA certificate and its private key.");
        }
    }
}