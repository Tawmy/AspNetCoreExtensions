namespace AspNetCoreExtensions.Keycloak.Options;

public record DataProtectionConfiguration
{
    /// <summary>
    ///     Path to PEM-formatted certificate used to encrypt data protection keys.
    /// </summary>
    public required string PathCertificate { get; init; }

    /// <summary>
    ///     Path to private key used to encrypt data protection keys.
    /// </summary>
    public required string PathPrivateKey { get; init; }

    /// <summary>
    ///     Path to secondary PEM-formatted certificate used to decrypt previously encrypted data protection keys.
    /// </summary>
    /// <remarks>
    ///     This certificate will not be used to encrypt new keys.It can be used to still be able to decrypt previously
    ///     encrypted keys if the primary <see cref="PathCertificate" /> is about to expire. <see cref="PathCertificate" />
    ///     then becomes <see cref="PathCertificateSecondary" /> and a new <see cref="PathCertificate" /> is set.
    /// </remarks>
    public string? PathCertificateSecondary { get; init; }

    /// <summary>
    ///     Path to secondary private key used to decrypt previously encrypted data protection keys.
    /// </summary>
    public string? PathPrivateKeySecondary { get; init; }
}