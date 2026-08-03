# Build stage
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

# Copy project files
COPY SecKit.csproj SecKit/
COPY SecKit.Web/SecKit.Web.csproj SecKit.Web/
COPY SecKit.Agent/SecKit.Agent.csproj SecKit.Agent/

# Restore dependencies
RUN dotnet restore SecKit.Web/SecKit.Web.csproj
RUN dotnet restore SecKit.Agent/SecKit.Agent.csproj

# Copy all source
COPY . .

# Build Web UI
RUN dotnet publish SecKit.Web/SecKit.Web.csproj -c Release -o /app/web --no-restore

# Build Agent
RUN dotnet publish SecKit.Agent/SecKit.Agent.csproj -c Release -o /app/agent --no-restore

# Build CLI
RUN dotnet publish SecKit.csproj -c Release -o /app/cli --no-restore

# Runtime stage
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS runtime
WORKDIR /app

# Install system dependencies for network tools
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        iproute2 \
        net-tools \
        procps \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -s /bin/bash seckit && \
    mkdir -p /app/reports /app/logs && \
    chown -R seckit:seckit /app

# Copy built artifacts
COPY --from=build /app/web ./web/
COPY --from=build /app/agent ./agent/
COPY --from=build /app/cli ./cli/

# Copy configuration
COPY appsettings.json ./appsettings.json

# Expose web UI port
EXPOSE 5000

# Default entry point: Web UI
# Override with: docker run --entrypoint /app/cli/seckit seckit --scan <url> --type full --i-am-authorized
USER seckit
ENV ASPNETCORE_URLS=http://0.0.0.0:5000
ENTRYPOINT ["dotnet", "/app/web/seckit-web.dll"]
