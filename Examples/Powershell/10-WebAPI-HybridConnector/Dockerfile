FROM mcr.microsoft.com/powershell

SHELL ["pwsh", "-command", "$ErrorActionPreference = 'Stop';"]
RUN Install-Module -Name "Pode" -Repository PSGallery -Force -AcceptLicense -Verbose -Scope AllUsers
RUN Install-Module -Name "PSWSMan" -Repository PSGallery -Force -AcceptLicense -Verbose -Scope AllUsers

RUN Install-WSMan

COPY . /usr/

EXPOSE 8080

#USER 1000

CMD ["pwsh","-File","/usr/startpode.ps1","-Verbose"]