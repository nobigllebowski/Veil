# syntax=docker/dockerfile:1.7
# ---------------------------------------------------------------------------------------------------
# Build: full SDK, restore separately from compile for layer caching.
# ---------------------------------------------------------------------------------------------------
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

COPY Directory.Build.props Directory.Packages.props global.json ./
# Project files of the API's dependency graph only, so the restore layer is reused until a reference changes.
COPY src/Veil.Crypto/Veil.Crypto.csproj                   src/Veil.Crypto/
COPY src/Veil.Contracts/Veil.Contracts.csproj             src/Veil.Contracts/
COPY src/Veil.Domain/Veil.Domain.csproj                   src/Veil.Domain/
COPY src/Veil.Application/Veil.Application.csproj         src/Veil.Application/
COPY src/Veil.Infrastructure/Veil.Infrastructure.csproj   src/Veil.Infrastructure/
COPY src/Veil.ServiceDefaults/Veil.ServiceDefaults.csproj src/Veil.ServiceDefaults/
COPY src/Veil.Client.Sdk/Veil.Client.Sdk.csproj           src/Veil.Client.Sdk/
COPY src/Veil.Web/Veil.Web.csproj                         src/Veil.Web/
COPY src/Veil.Api/Veil.Api.csproj                         src/Veil.Api/
RUN dotnet restore src/Veil.Api/Veil.Api.csproj

COPY src/ src/
RUN dotnet publish src/Veil.Api/Veil.Api.csproj -c Release -o /app --no-restore \
    /p:UseAppHost=false /p:ContinuousIntegrationBuild=true

# ---------------------------------------------------------------------------------------------------
# Runtime: chiseled Ubuntu (no shell, no package manager), non-root, read-only friendly.
# ---------------------------------------------------------------------------------------------------
FROM mcr.microsoft.com/dotnet/aspnet:10.0-noble-chiseled AS runtime
WORKDIR /app
COPY --from=build /app .

ENV ASPNETCORE_URLS=http://+:8080 \
    ASPNETCORE_ENVIRONMENT=Production \
    DOTNET_EnableDiagnostics=0 \
    Https__Redirect=false

EXPOSE 8080
USER app
ENTRYPOINT ["dotnet", "Veil.Api.dll"]
