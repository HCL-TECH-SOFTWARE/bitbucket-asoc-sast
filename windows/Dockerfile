FROM mcr.microsoft.com/dotnet/sdk:5.0.401-windowsservercore-ltsc2019

RUN powershell -Command (Get-WMIObject win32_operatingsystem).name

COPY requirements.txt /
RUN pip install -r /requirements.txt

COPY pipe /
COPY LICENSE pipe.yml README.md /

ENTRYPOINT ["py", "/RunSAST.py"]
