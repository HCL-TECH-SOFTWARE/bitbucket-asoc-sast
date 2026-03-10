FROM mcr.microsoft.com/dotnet/sdk:5.0.401-windowsservercore-ltsc2019

RUN powershell -Command (Get-WMIObject win32_operatingsystem).name

# Install Python with restricted permissions
RUN powershell -Command " \
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; \
    Invoke-WebRequest -Uri https://www.python.org/ftp/python/3.9.13/python-3.9.13-amd64.exe -OutFile python-installer.exe; \
    Start-Process python-installer.exe -ArgumentList '/quiet InstallAllUsers=1 PrependPath=1' -Wait; \
    Remove-Item python-installer.exe \
"

# Build context must be the repository root:
#   docker build -f windows/Dockerfile .
COPY windows/requirements.txt /
RUN pip install -r /requirements.txt

# Create app directory with controlled permissions
RUN powershell -Command "New-Item -ItemType Directory -Path 'C:\app' -Force | Out-Null"

# Shared modules from common/
COPY common/__init__.py common/constants.py common/ASoC.py common/RunSASTBase.py /app/
# Platform-specific thin subclass + config
COPY windows/pipe/__init__.py windows/pipe/platform_config.py windows/pipe/RunSAST.py /app/
COPY windows/LICENSE windows/pipe.yml windows/README.md /app/

WORKDIR /app

# Run as non-administrator to prevent privilege escalation
USER ContainerUser

ENTRYPOINT ["py", "/app/RunSAST.py"]