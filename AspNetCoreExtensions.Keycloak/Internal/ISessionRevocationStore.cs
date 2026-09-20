namespace AspNetCoreExtensions.Keycloak.Internal;

/// <summary>
/// Revocation by identity rather than by cookie key for OAuth backchannel logout.
/// </summary>
internal interface ISessionRevocationStore
{
    /// <summary>Revoke the session with the given Keycloak session id.</summary>
    /// <returns>Number of sessions revoked.</returns>
    Task<int> RevokeSessionAsync(string sid, CancellationToken cancellationToken = default);

    /// <summary>Revoke every session belonging to the given subject.</summary>
    /// <returns>Number of sessions revoked.</returns>
    Task<int> RevokeUserSessionsAsync(string sub, CancellationToken cancellationToken = default);
}