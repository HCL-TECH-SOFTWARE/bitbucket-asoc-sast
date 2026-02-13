FROM mcr.microsoft.com/dotnet/sdk:5.0.401-windowsservercore-ltsc2019

RUN powershell -Command (Get-WMIObject win32_operatingsystem).name

# Install Python
RUN powershell -Command " \
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; \
    Invoke-WebRequest -Uri https://www.python.org/ftp/python/3.9.13/python-3.9.13-amd64.exe -OutFile python-installer.exe; \
    Start-Process python-installer.exe -ArgumentList '/quiet InstallAllUsers=1 PrependPath=1' -Wait; \
    Remove-Item python-installer.exe \
"

COPY requirements.txt /
RUN pip install -r /requirements.txt

COPY pipe /
COPY LICENSE pipe.yml README.md /

ENTRYPOINT ["py", "/RunSAST.py"]