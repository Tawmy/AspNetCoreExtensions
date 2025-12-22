using System.Buffers.Text;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Tokens;

namespace AspNetCoreExtensions.OpenIdConnect.Keycloak;

internal class JwtFactory(SecurityKey securityKey, X509Certificate2 cert, string oidcAuthority, string oidcClientId)
{
    public string GenerateToken()
    {
        var signingCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.EcdsaSha256);

        var tokenHandler = new JwtSecurityTokenHandler();
        var tokenDescriptor = CreateSecurityTokenDescriptor(signingCredentials);
        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }

    private SecurityTokenDescriptor CreateSecurityTokenDescriptor(SigningCredentials signingCredentials)
    {
        var certHash = SHA256.HashData(cert.RawData);
        var x5T256 = Base64Url.EncodeToString(certHash);

        return new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity([
                new Claim(JwtRegisteredClaimNames.Sub, oidcClientId),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.CreateVersion7().ToString())
            ]),
            IssuedAt = DateTime.UtcNow,
            Expires = DateTime.UtcNow.AddSeconds(60),
            Issuer = oidcClientId,
            Audience = oidcAuthority, // TODO should this be token endpoint?
            AdditionalHeaderClaims = new Dictionary<string, object>
            {
                {
                    "kid", x5T256
                }
            },

            SigningCredentials = signingCredentials
        };
    }
}