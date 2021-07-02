FROM mcr.microsoft.com/powershell:alpine-3.12

RUN pwsh -c Install-Module -Name Pode -Repository PSGallery -Force -AcceptLicense -Verbose -Scope AllUsers

COPY . /usr/

EXPOSE 8080

USER 1000

CMD ["pwsh","-File","/usr/startpode.ps1","-Verbose"]