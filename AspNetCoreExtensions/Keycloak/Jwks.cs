using System.Buffers.Text;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Serialization;
using Microsoft.IdentityModel.Tokens;

namespace AspNetCoreExtensions.Keycloak;

internal class JwksProvider(string certificateUri)
{
    private readonly JwksResponse _response = LoadData(certificateUri);

    public JwksResponse GetJwksResponse()
    {
        return _response;
    }

    private static JwksResponse LoadData(string certificateUri)
    {
        using var cert = X509CertificateLoader.LoadCertificateFromFile(certificateUri);

        if (cert.GetECDsaPublicKey() is not { } publicKey)
        {
            throw new InvalidOperationException("Certificate is not ECDSA.");
        }

        var ecParams = publicKey.ExportParameters(false);

        if (ecParams.Q.X is null || ecParams.Q.Y is null)
        {
            throw new InvalidOperationException("Invalid ECDSA parameters: X or Y coordinate is null.");
        }

        var certHash = SHA256.HashData(cert.RawData);
        var x5T256 = Base64Url.EncodeToString(certHash);

        return new JwksResponse
        {
            Keys =
            [
                new JwksKey
                {
                    Kid = x5T256,
                    Kty = "EC",
                    Alg = GetAlgorithm(publicKey.KeySize),
                    Use = "sig",
                    X5C = [Convert.ToBase64String(cert.Export(X509ContentType.Cert))],
                    X5Ts256 = x5T256,
                    Crv = GetCurveName(ecParams.Curve.Oid.Value, publicKey.KeySize),
                    X = Base64Url.EncodeToString(ecParams.Q.X),
                    Y = Base64Url.EncodeToString(ecParams.Q.Y)
                }
            ]
        };
    }

    private static string GetCurveName(string? curveOid, int keySize)
    {
        return (curveOid, keySize) switch
        {
            ("1.2.840.10045.3.1.7", 256) => "P-256",
            _ => throw new InvalidOperationException($"Unsupported EC curve. OID: {curveOid}, KeySize: {keySize}")
        };
    }

    private static string GetAlgorithm(int keySize)
    {
        return keySize switch
        {
            256 => SecurityAlgorithms.EcdsaSha256,
            _ => throw new InvalidOperationException($"Unsupported key size: {keySize}")
        };
    }
}

internal record JwksResponse
{
    public required JwksKey[] Keys { get; init; }
}

internal record JwksKey
{
    public required string Kid { get; init; }
    public required string Kty { get; init; }
    public required string Alg { get; init; }
    public required string Use { get; init; }

    [JsonPropertyName("x5c")] public required string[] X5C { get; init; }

    [JsonPropertyName("x5t#S256")] public required string X5Ts256 { get; init; }

    public required string Crv { get; init; }
    public required string X { get; init; }
    public required string Y { get; init; }
}