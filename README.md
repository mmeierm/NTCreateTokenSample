# NTCreateTokenSample
Sample Project that uses NTCreateToken to elevate a process in user context
Requires calling User to have Admin privileges and additional SeCreateTokenPrivilege, SeTcbPrivilege and SeAssignPrimaryTokenPrivilege (Can be assigned via User Rights Assignment in secpol.mmc)

Useage:  
NTCreateTokenSample.exe Domain\Account  
  
Example:  
NTCreateTokenSample.exe AzureAD\user@test.onmicrosoft.com

All scripts are provided "AS IS" with no liability and should always be tested in a test environment before used in production!
