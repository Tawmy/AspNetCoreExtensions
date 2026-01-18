FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS base
USER $APP_UID
WORKDIR /app
EXPOSE 8080

FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
ARG TARGETARCH
ARG BUILD_CONFIGURATION=Release
WORKDIR /src

RUN case "${TARGETARCH}" in \
        "arm64")  TW_ARCH="arm64" ;; \
        *)        TW_ARCH="x64" ;; \
    esac && \
    curl -sLO https://github.com/tailwindlabs/tailwindcss/releases/download/v4.1.18/tailwindcss-linux-${TW_ARCH} && \
    chmod +x tailwindcss-linux-${TW_ARCH} && \
    mv tailwindcss-linux-${TW_ARCH} /usr/local/bin/tailwindcss

COPY ["AspNetCoreExtensions.Sample/AspNetCoreExtensions.Sample.csproj", "AspNetCoreExtensions.Sample/"]
COPY ["AspNetCoreExtensions.Sample.Client/AspNetCoreExtensions.Sample.Client.csproj", "AspNetCoreExtensions.Sample.Client/"]
RUN dotnet restore "AspNetCoreExtensions.Sample/AspNetCoreExtensions.Sample.csproj"
COPY . .
WORKDIR "/src/AspNetCoreExtensions.Sample"
RUN dotnet build "./AspNetCoreExtensions.Sample.csproj" -c $BUILD_CONFIGURATION -o /app/build

FROM build AS publish
ARG BUILD_CONFIGURATION=Release
RUN dotnet publish "./AspNetCoreExtensions.Sample.csproj" -c $BUILD_CONFIGURATION -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "AspNetCoreExtensions.Sample.dll"]
