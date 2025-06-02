# Check if Chocolatey is installed
if (!(Get-Command choco.exe -ErrorAction SilentlyContinue)) {
    Write-Host "Installing Chocolatey..."
    Set-ExecutionPolicy Bypass -Scope Process -Force
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
    Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
}

# Install OpenSSL
Write-Host "Installing OpenSSL..."
choco install openssl -y

# Refresh environment variables
$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")

# Create certificates directory
$certPath = ".\certificates"
New-Item -ItemType Directory -Force -Path $certPath

# Generate SSL certificate
Write-Host "Generating SSL certificate..."
$opensslPath = "C:\Program Files\OpenSSL-Win64\bin\openssl.exe"
& $opensslPath req -x509 -newkey rsa:4096 -keyout "$certPath\key.pem" -out "$certPath\cert.pem" -days 365 -nodes -subj "/CN=localhost"

Write-Host "SSL certificates generated successfully!"
Write-Host "Certificates location: $((Get-Item $certPath).FullName)"
