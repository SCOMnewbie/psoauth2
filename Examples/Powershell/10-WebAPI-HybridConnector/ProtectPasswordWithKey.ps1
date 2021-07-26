#Generate a random 256 bit AES key
$Key = New-Object Byte[] 32
[Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($Key)

#Generate the encrypted password file with the previously created key and store it into a specific path.
"your password" | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString -Key $key | Out-File 'C:\TEMP\secret.txt'

# Create a PSCredential from the encrypted file with the key  
# $OrgCreds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList 'Corp SamAccountName', (Get-Content 'C:\TEMP\secret.txt' | ConvertTo-SecureString -Key $key)
# Get-aduser "blabla" -credential $Orgcreds