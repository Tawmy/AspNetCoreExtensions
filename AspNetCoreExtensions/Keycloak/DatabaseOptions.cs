namespace AspNetCoreExtensions.Keycloak;

public record DatabaseOptions
{
    public required string Host { get; init; }
    public required string Database { get; init; }
    public required string Username { get; init; }
    public required string Password { get; init; }

    public string ConnectionString => $"Host={Host};Database={Database};Username={Username};Password={Password}";
}