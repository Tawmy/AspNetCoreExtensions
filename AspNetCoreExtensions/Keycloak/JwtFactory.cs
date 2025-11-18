using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;

namespace AspNetCoreExtensions.Keycloak;

internal class JwtFactory(SecurityKey securityKey, string oidcAuthority, string oidcClientId)
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

            SigningCredentials = signingCredentials
        };
    }
}