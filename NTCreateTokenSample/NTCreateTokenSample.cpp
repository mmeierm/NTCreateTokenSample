#include <Windows.h>
#include <winternl.h>
#include <sddl.h>
#include <stdio.h>
#include <Aclapi.h>
#include <userenv.h>
#include <tlhelp32.h>
#include <string>
#include <vector>
#include <cwchar> // For wcstombs

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "userenv.lib")

typedef NTSTATUS(NTAPI* PFN_NtCreateToken)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, TOKEN_TYPE, PLUID, PLARGE_INTEGER,
    PTOKEN_USER, PTOKEN_GROUPS, PTOKEN_PRIVILEGES, PTOKEN_OWNER, PTOKEN_PRIMARY_GROUP,
    PTOKEN_DEFAULT_DACL, PTOKEN_SOURCE
    );

// Helperfunction: Get User-SID from UPN (User Principal Name) or username
BOOL GetUserSidFromName(LPCSTR userName, PSID* ppSid) {
    DWORD sidSize = 0, domainSize = 0;
    SID_NAME_USE use;
    LookupAccountNameA(NULL, userName, NULL, &sidSize, NULL, &domainSize, &use);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) return FALSE;
    *ppSid = (PSID)LocalAlloc(LPTR, sidSize);
    CHAR* domain = (CHAR*)LocalAlloc(LPTR, domainSize);
    BOOL ok = LookupAccountNameA(NULL, userName, *ppSid, &sidSize, domain, &domainSize, &use);
    LocalFree(domain);
    return ok;
}

// Helperfunction: Get the user token of an interactive user by matching the SID
HANDLE FindUserToken(PSID pTargetSid) {
    HANDLE hToken = NULL;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return NULL;

    PROCESSENTRY32 pe = { 0 };
    pe.dwSize = sizeof(pe);

    if (Process32First(hSnap, &pe)) {
        do {
			// explorer.exe is the shell process for the user, we will use it to get the token
            char exeFile[MAX_PATH];
            wcstombs_s(nullptr, exeFile, MAX_PATH, pe.szExeFile, _TRUNCATE);

            if (_stricmp(exeFile, "explorer.exe") == 0) {
                HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pe.th32ProcessID);
                if (hProc) {
                    HANDLE hProcToken = NULL;
                    if (OpenProcessToken(hProc, TOKEN_QUERY | TOKEN_DUPLICATE, &hProcToken)) {
                        // SID compare
                        DWORD len = 0;
                        GetTokenInformation(hProcToken, TokenUser, NULL, 0, &len);
                        PTOKEN_USER pUser = (PTOKEN_USER)LocalAlloc(LPTR, len);
                        if (GetTokenInformation(hProcToken, TokenUser, pUser, len, &len)) {
                            if (EqualSid(pUser->User.Sid, pTargetSid)) {
                                // Token duplicate
                                HANDLE hDup = NULL;
                                if (DuplicateTokenEx(hProcToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hDup)) {
                                    LocalFree(pUser);
                                    CloseHandle(hProcToken);
                                    CloseHandle(hProc);
                                    CloseHandle(hSnap);
                                    return hDup;
                                }
                            }
                        }
                        LocalFree(pUser);
                        CloseHandle(hProcToken);
                    }
                    CloseHandle(hProc);
                }
            }
        } while (Process32Next(hSnap, &pe));
    }
    CloseHandle(hSnap);
    return NULL;
}

// Debug-Output-Funktionen
void PrintSid(const char* label, PSID sid) {
    char* sidStr = NULL;
    if (sid && ConvertSidToStringSidA(sid, &sidStr)) {
        printf("%s: %s\n", label, sidStr);
        LocalFree(sidStr);
    }
    else {
        printf("%s: <invalid>\n", label);
    }
}

void PrintGroups(PTOKEN_GROUPS groups) {
    printf("Gruppen (%lu):\n", groups->GroupCount);
    for (DWORD i = 0; i < groups->GroupCount; ++i) {
        char* sidStr = NULL;
        if (ConvertSidToStringSidA(groups->Groups[i].Sid, &sidStr)) {
            printf("  [%2lu] %s  Attributes: 0x%08lX\n", i, sidStr, groups->Groups[i].Attributes);
            LocalFree(sidStr);
        }
        else {
            printf("  [%2lu] <invalid>  Attributes: 0x%08lX\n", i, groups->Groups[i].Attributes);
        }
    }
}

void PrintPrivileges(PTOKEN_PRIVILEGES privs) {
    printf("Privilegien (%lu):\n", privs->PrivilegeCount);
    for (DWORD i = 0; i < privs->PrivilegeCount; ++i) {
        char name[128] = { 0 };
        DWORD nameLen = sizeof(name);
        if (LookupPrivilegeNameA(NULL, &privs->Privileges[i].Luid, name, &nameLen)) {
            printf("  [%2lu] %s  Attributes: 0x%08lX\n", i, name, privs->Privileges[i].Attributes);
        }
        else {
            printf("  [%2lu] <unknown>  Attributes: 0x%08lX\n", i, privs->Privileges[i].Attributes);
        }
    }
}

int main(int argc, char* argv[])
{
    if (argc != 2) {
        printf("Usage: %s <Domain\\Username>\n", argv[0]);
        return 1;
    }

    // 1. Get User-SID
    const char* userName = argv[1];
    PSID pUserSid = NULL;
    if (!GetUserSidFromName(userName, &pUserSid)) {
        printf("Get User-SID failed: %lu\n", GetLastError());
        return 1;
    }

    // 2. Get Token of Users
    HANDLE hUserToken = FindUserToken(pUserSid);
    if (!hUserToken) {
        printf("No Prozess-Token found for the User!\n");
        LocalFree(pUserSid);
        return 1;
    }

    // 3. Read Groups and add the Admin SID
    DWORD groupLen = 0;
    GetTokenInformation(hUserToken, TokenGroups, NULL, 0, &groupLen);
    PTOKEN_GROUPS pOrigGroups = (PTOKEN_GROUPS)LocalAlloc(LPTR, groupLen);
    if (!GetTokenInformation(hUserToken, TokenGroups, pOrigGroups, groupLen, &groupLen)) {
        printf("GetTokenInformation(TokenGroups) failed: %lu\n", GetLastError());
        CloseHandle(hUserToken);
        LocalFree(pUserSid);
        return 1;
    }
    DWORD newGroupCount = pOrigGroups->GroupCount + 1;
    DWORD newGroupsSize = sizeof(TOKEN_GROUPS) + (newGroupCount - 1) * sizeof(SID_AND_ATTRIBUTES);
    PTOKEN_GROUPS pGroups = (PTOKEN_GROUPS)LocalAlloc(LPTR, newGroupsSize);
    pGroups->GroupCount = newGroupCount;
    for (DWORD i = 0; i < pOrigGroups->GroupCount; ++i) {
        pGroups->Groups[i].Sid = pOrigGroups->Groups[i].Sid;
        pGroups->Groups[i].Attributes = pOrigGroups->Groups[i].Attributes;
    }
    PSID pAdminSid = NULL;
    if (!ConvertStringSidToSidA("S-1-5-32-544", &pAdminSid)) {
        printf("ConvertStringSidToSidA failed: %lu\n", GetLastError());
        // Cleanup...
        return 1;
    }
    pGroups->Groups[newGroupCount - 1].Sid = pAdminSid;
    pGroups->Groups[newGroupCount - 1].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY;

    // 4. User, Primary Group (set to User-SID, but copy it first)
    DWORD userLen = 0;
    GetTokenInformation(hUserToken, TokenUser, NULL, 0, &userLen);
    PTOKEN_USER pUser = (PTOKEN_USER)LocalAlloc(LPTR, userLen);
    GetTokenInformation(hUserToken, TokenUser, pUser, userLen, &userLen);

    // Set Primary Group explicit to copy of the User-SID 
    DWORD sidLen = GetLengthSid(pUser->User.Sid);
    PSID pPrimaryGroupSid = LocalAlloc(LPTR, sidLen);
    if (!CopySid(sidLen, pPrimaryGroupSid, pUser->User.Sid)) {
        printf("CopySid f�r PrimaryGroup failed: %lu\n", GetLastError());
        // Cleanup...
        return 1;
    }
    PTOKEN_PRIMARY_GROUP pPrimaryGroup = (PTOKEN_PRIMARY_GROUP)LocalAlloc(LPTR, sizeof(TOKEN_PRIMARY_GROUP));
    pPrimaryGroup->PrimaryGroup = pPrimaryGroupSid;

    // Get Default DACL und Privileges of Admin-Process (SYSTEM/Admin-Token)
    HANDLE hSelfToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hSelfToken)) {
        printf("OpenProcessToken failed: %lu\n", GetLastError());
        // Cleanup...
        return 1;
    }
    DWORD adminDaclLen = 0;
    GetTokenInformation(hSelfToken, TokenDefaultDacl, NULL, 0, &adminDaclLen);
    PTOKEN_DEFAULT_DACL pDefaultDacl = (PTOKEN_DEFAULT_DACL)LocalAlloc(LPTR, adminDaclLen);
    if (!GetTokenInformation(hSelfToken, TokenDefaultDacl, pDefaultDacl, adminDaclLen, &adminDaclLen)) {
        printf("GetTokenInformation(TokenDefaultDacl, Admin) failed: %lu\n", GetLastError());
        CloseHandle(hSelfToken);
        // Cleanup...
        return 1;
    }
    DWORD privLen = 0;
    GetTokenInformation(hSelfToken, TokenPrivileges, NULL, 0, &privLen);
    PTOKEN_PRIVILEGES pPrivs = (PTOKEN_PRIVILEGES)LocalAlloc(LPTR, privLen);
    if (!GetTokenInformation(hSelfToken, TokenPrivileges, pPrivs, privLen, &privLen)) {
        printf("GetTokenInformation(TokenPrivileges) failed: %lu\n", GetLastError());
        CloseHandle(hSelfToken);
        // Cleanup...
        return 1;
    }
    CloseHandle(hSelfToken);

    // 5. Set Owner to User-SID 
    PTOKEN_OWNER pOwner = (PTOKEN_OWNER)LocalAlloc(LPTR, sizeof(TOKEN_OWNER));
    pOwner->Owner = pUser->User.Sid;

	// 6. Set Token Integrity Level to High (S-1-16-12288) und if exists, remove S-1-16-8192 (Medium IL)
    PSID pHighIL = NULL;
    if (!ConvertStringSidToSidA("S-1-16-12288", &pHighIL)) {
        printf("ConvertStringSidToSidA (High IL) failed: %lu\n", GetLastError());
        // Cleanup...
        return 1;
    }
    TOKEN_MANDATORY_LABEL tml = { 0 };
    tml.Label.Attributes = SE_GROUP_INTEGRITY;
    tml.Label.Sid = pHighIL;

	// Replace S-1-16-8192 with S-1-16-12288 in the groups array
    std::vector<PSID> highIlCopies;
    for (DWORD i = 0; i < pGroups->GroupCount; ++i) {
        char* sidStr = NULL;
        if (ConvertSidToStringSidA(pGroups->Groups[i].Sid, &sidStr)) {
            if (_stricmp(sidStr, "S-1-16-8192") == 0) {
                PSID pHighILCopy = LocalAlloc(LPTR, GetLengthSid(pHighIL));
                if (CopySid(GetLengthSid(pHighIL), pHighILCopy, pHighIL)) {
					// The original SID is still used in the token.
                    pGroups->Groups[i].Sid = pHighILCopy;
                    highIlCopies.push_back(pHighILCopy);
                }
                else {
                    printf("CopySid for HighIL in group failed: %lu\n", GetLastError());
                }
            }
            LocalFree(sidStr);
        }
    }

    // Debug-Output before calling NtCreateToken
    printf("\n==== Debug-Output for NtCreateToken ====\n");
    PrintSid("User-SID", pUser->User.Sid);
    PrintGroups(pGroups);
    PrintPrivileges(pPrivs);
    PrintSid("Owner", pOwner->Owner);
    PrintSid("PrimaryGroup", pPrimaryGroup->PrimaryGroup);
    if (pDefaultDacl && pDefaultDacl->DefaultDacl) {
        printf("Default DACL found.\n");
    }
    else {
        printf("Default DACL: <none>\n");
    }
    printf("=========================================\n\n");

    // 8. LUID, Zeit, etc. (authId of Userprozess)
    TOKEN_STATISTICS tokenStats = { 0 };
    DWORD statsLen = 0;
    if (!GetTokenInformation(hUserToken, TokenStatistics, &tokenStats, sizeof(tokenStats), &statsLen)) {
        printf("GetTokenInformation(TokenStatistics) failed: %lu\n", GetLastError());
        // Cleanup...
        return 1;
    }
    LUID authId = tokenStats.AuthenticationId;

    LARGE_INTEGER expTime = { 0 };
    expTime.QuadPart = -1; // Never expire

    // 9. Token-Source
    TOKEN_SOURCE source = { 0 };
    strcpy_s(source.SourceName, sizeof(source.SourceName), "S4UWin");
    AllocateLocallyUniqueId(&source.SourceIdentifier);

	// 10. Empty Objekt-Attbutes-Struktur
    OBJECT_ATTRIBUTES objAttr = { 0 };
    objAttr.Length = sizeof(OBJECT_ATTRIBUTES);

    // 11. NtCreateToken enumerate
    PFN_NtCreateToken NtCreateToken = (PFN_NtCreateToken)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtCreateToken");
    if (!NtCreateToken) {
        printf("NtCreateToken not found!\n");
        // Cleanup...
        return 1;
    }

    // Enable SeTcbPrivilege und SeCreateTokenPrivilege 
    HANDLE hProcToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hProcToken)) {
        TOKEN_PRIVILEGES tp = { 0 };
        LUID luidTcb, luidCreateToken;
        int privCount = 0;

        if (LookupPrivilegeValueA(NULL, "SeTcbPrivilege", &luidTcb)) {
            tp.Privileges[privCount].Luid = luidTcb;
            tp.Privileges[privCount].Attributes = SE_PRIVILEGE_ENABLED;
            ++privCount;
        }
        if (LookupPrivilegeValueA(NULL, "SeCreateTokenPrivilege", &luidCreateToken)) {
            tp.Privileges[privCount].Luid = luidCreateToken;
            tp.Privileges[privCount].Attributes = SE_PRIVILEGE_ENABLED;
            ++privCount;
        }
        tp.PrivilegeCount = privCount;
        if (privCount > 0) {
            AdjustTokenPrivileges(hProcToken, FALSE, &tp, sizeof(tp), NULL, NULL);
			// ignore error, as AdjustTokenPrivileges can give GetLastError() != 0 even if it succeeds
        }
        CloseHandle(hProcToken);
    }

    // 12. create Token 
    HANDLE hToken = NULL;
    NTSTATUS status = NtCreateToken(
        &hToken,
        TOKEN_ALL_ACCESS,
        &objAttr,
        TokenPrimary,
        &authId,
        &expTime,
        pUser,
        pGroups,
        pPrivs,
        pOwner,           
        pPrimaryGroup,   
        pDefaultDacl,     
        &source
    );

    if (status == 0) {
		// Get Session-ID of initial process (User-Token)
        DWORD userSessionId = 0;
        DWORD sessionIdLen = sizeof(DWORD);
        if (!GetTokenInformation(hUserToken, TokenSessionId, &userSessionId, sizeof(userSessionId), &sessionIdLen)) {
            printf("GetTokenInformation(TokenSessionId) failed: %lu\n", GetLastError());
            // Cleanup...
            return 1;
        }
        if (!SetTokenInformation(hToken, TokenSessionId, &userSessionId, sizeof(userSessionId))) {
            printf("SetTokenInformation(TokenSessionId) failed: %lu\n", GetLastError());
            // Cleanup...
            return 1;
        }

        // Integrity Level High setzen
        if (!SetTokenInformation(hToken, TokenIntegrityLevel, &tml, sizeof(TOKEN_MANDATORY_LABEL) + GetLengthSid(pHighIL))) {
            printf("SetTokenInformation(TokenIntegrityLevel) failed: %lu\n", GetLastError());
        }
    }

    if (status != 0) {
        printf("NtCreateToken failed: 0x%08X\n", status);
        // Cleanup...
        for (PSID sid : highIlCopies) LocalFree(sid);
        LocalFree(pHighIL);
        LocalFree(pUserSid);
        LocalFree(pGroups);
        LocalFree(pPrivs);
        LocalFree(pUser);
        LocalFree(pPrimaryGroupSid);
        LocalFree(pPrimaryGroup);
        LocalFree(pOwner);
        LocalFree(pDefaultDacl);
        LocalFree(pOrigGroups);
        return 1;
    }

    printf("Token created sucessfully\n");

	// Create Environment Block for the new Token
    LPVOID env = NULL;
    if (!CreateEnvironmentBlock(&env, hToken, FALSE)) {
        printf("CreateEnvironmentBlock failed: %lu\n", GetLastError());
        env = NULL;
    }

	// Start a new process with the created token
    STARTUPINFO si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    WCHAR cmdLine[512] = L"cmd.exe";
    BOOL result = CreateProcessAsUserW(
        hToken, NULL, cmdLine, NULL, NULL, FALSE,
        CREATE_UNICODE_ENVIRONMENT, env, L"C:\\Windows\\system32", &si, &pi);

    if (result) {
        printf("Process started (PID: %lu)\n", pi.dwProcessId);
        WaitForSingleObject(pi.hProcess, INFINITE);
        DWORD exitCode = 0;
        if (GetExitCodeProcess(pi.hProcess, &exitCode))
            printf("Process ExitCode: %lu\n", exitCode);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
    else {
        printf("CreateProcessAsUserW failed: %lu\n", GetLastError());
    }

    if (env) DestroyEnvironmentBlock(env);
    CloseHandle(hToken);
    CloseHandle(hUserToken);

	// Cleanup: Only free allocated memory, handles are closed
    for (PSID sid : highIlCopies) LocalFree(sid);
    LocalFree(pHighIL);
    LocalFree(pUserSid);
    LocalFree(pGroups);
    LocalFree(pPrivs);
    LocalFree(pUser);
    LocalFree(pPrimaryGroupSid);
    LocalFree(pPrimaryGroup);
    LocalFree(pOwner);
    LocalFree(pDefaultDacl);
    LocalFree(pOrigGroups);
    return 0;
}