using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Duende.IdentityModel.Client;
using Microsoft.IdentityModel.Tokens;

namespace AspNetCoreExtensions.Keycloak;

/// <summary>
///     Generates a JWT assertion for signed JWT client authentication.
/// </summary>
/// <param name="oidcAuthority">OpenID Connect Authority (realm URL)</param>
/// <param name="oidcClientId">OpenID Connect Client ID</param>
/// <param name="certificateUri">
///     Path under which certificate is located. May be null if signed JWT client authentication
///     is not used.
/// </param>
/// <param name="privateKeyUri">
///     Path under which private key is located. May be null if signed JWT client authentication is
///     not used.
/// </param>
internal class ClientAssertionService(
    string oidcAuthority,
    string oidcClientId,
    string? certificateUri,
    string? privateKeyUri)
{
    private const string AssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    private readonly X509Certificate2? _certificate =
        certificateUri is not null ? X509CertificateLoader.LoadCertificateFromFile(certificateUri) : null;

    private readonly SecurityKey? _securityKey = privateKeyUri is not null ? CreateSecurityKey(privateKeyUri) : null;

    public bool UseSignedJwtClientAuthentication()
    {
        return _securityKey is not null;
    }

    public ClientAssertion CreateSignedJwtAssertion()
    {
        if (_securityKey is null)
        {
            throw new InvalidOperationException("Security key must be loaded.");
        }

        if (_certificate is null)
        {
            throw new InvalidOperationException("Certificate must be loaded.");
        }

        return new ClientAssertion
        {
            Type = AssertionType,
            Value = new JwtFactory(_securityKey, _certificate, oidcAuthority, oidcClientId).GenerateToken()
        };
    }

    private static ECDsaSecurityKey CreateSecurityKey(string certificateUri)
    {
        var ecdsa = ECDsa.Create();
        ecdsa.ImportFromPem(File.ReadAllText(certificateUri));
        return new ECDsaSecurityKey(ecdsa);
    }
}