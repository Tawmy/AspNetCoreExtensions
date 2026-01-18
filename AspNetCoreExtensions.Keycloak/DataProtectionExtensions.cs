using System.Security.Cryptography.X509Certificates;
using AspNetCoreExtensions.Keycloak.Internal.Db;
using AspNetCoreExtensions.Keycloak.Options;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace AspNetCoreExtensions.Keycloak;

public static class DataProtectionExtensions
{
    extension(IServiceCollection services)
    {
        public void AddDataProtection(DataProtectionConfiguration config)
        {
            var cert = X509Certificate2.CreateFromPemFile(config.PathCertificate, config.PathPrivateKey);

            X509Certificate2[] decryptionCerts;
            if (config is { PathCertificateSecondary: not null, PathPrivateKeySecondary: not null })
            {
                // alternative certificate for decryption provided, use both
                var certSecondary = X509Certificate2.CreateFromPemFile(config.PathCertificateSecondary,
                    config.PathPrivateKeySecondary);
                decryptionCerts = [cert, certSecondary];
            }
            else
            {
                // only one certificate provided
                decryptionCerts = [cert];
            }

            if (!services.Any(x => x.ServiceType is IDataProtectionKeyContext))
            {
                services.AddDbContext<DataProtectionKeyContext>();
            }

            services.AddDataProtection()
                .PersistKeysToDbContext<DataProtectionKeyContext>()
                .ProtectKeysWithCertificate(cert)
                .UnprotectKeysWithAnyCertificate(decryptionCerts);
        }
    }
}