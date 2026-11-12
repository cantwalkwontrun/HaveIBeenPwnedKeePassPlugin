---
lang: en-GB
---

# Have I Been Pwned KeePass Plugin

## Maintenance fork

This development fork fixes stale asynchronous results, history/editor-copy checks, HTTP error handling and breach metadata. See [REVIEW.md](./REVIEW.md) for findings, verification and limitations.

No fork release binaries have been published. The installation links below point to the original upstream release, which does not include these changes. Update checks are disabled in this development build until a fork release and its update manifest are available.

## Building and testing

Install the .NET SDK and .NET Framework 4.7.2 targeting pack on Windows. Extract a verified [official KeePass portable package](https://keepass.info/download.html) into `KeePass-2.X` at the repository root. This folder supplies `KeePass.exe` as a build reference; use a separate test copy, because Debug builds place the plugin in its `Plugins` directory.

```powershell
dotnet restore HaveIBeenPwnedKeePassPlugin/HaveIBeenPwnedPlugin.csproj
dotnet build HaveIBeenPwnedKeePassPlugin/HaveIBeenPwnedPlugin.csproj -c Release --no-restore
dotnet build tests/RegressionTests.csproj -c Release
./tests/bin/Release/net472/RegressionTests.exe
```

The regression harness uses synthetic in-memory entries and fake HTTP responses. Add `--live` to make one real range request for the synthetic hash in the HIBP documentation. It does not open or save a password database. Release output is `HaveIBeenPwnedKeePassPlugin/bin/Release/HaveIBeenPwnedPlugin.dll`.

Optional companion-plugin checks accept `--dashboarder` followed by a locally built Dashboarder DLL and `--fluent` followed by the Fluent Theme v1.5.2026.1111 DLL. These test specific mutation/rendering paths; see the review for the scope and remaining manual checks.

## Original plugin


Simple [KeePass plugin] which uses the service [Have I Been Pwned](https://haveibeenpwned.com/) from [Troy Hunt](https://www.troyhunt.com)

Your password never leaves KeePass! This is ensured by using a [k-Anonymity model] when searching with [Pwned Passwords].

> In order to protect the value of the source password being searched for, Pwned Passwords also implements a k-Anonymity model that allows a password to be searched for by partial hash. This allows the first 5 characters of either a SHA-1 or an NTLM hash (not case-sensitive) to be passed to the API

## [Changelog](./CHANGELOG.md)

## Installation and Updates
### Requirements
#### Windows
 - [.NET Framework 4.7.2](https://dotnet.microsoft.com/download/thank-you/net472) or higher

#### Linux
 - [Mono 5.18](https://www.mono-project.com/docs/about-mono/releases/5.18.0/) or higher
 - On some Linux systems, the `mono-complete` package may be required for plugins to work properly ([Details on keepass.info](https://keepass.info/help/v2/setup.html#mono))

### How to install/update
 1. Download the [latest release (.dll file) from GitHub](https://github.com/kapsiR/HaveIBeenPwnedKeePassPlugin/releases)
 2. In KeePass, click 'Tools' → 'Plugins' → button 'Open Folder'  
    *KeePass now opens a folder called 'Plugins'*
 3. Exit KeePass to free up the lock on the plugin
 4. Move the plugin file into the 'Plugins' folder (replace if exists already)  
 5. Start KeePass again

### Uninstall 
 1. In KeePass, click 'Tools' → 'Plugins' → button 'Open Folder'  
    *KeePass now opens a folder called 'Plugins'*  
 2. Exit KeePass to free up the lock on the plugin
 3. Delete the plugin file

## Some impressions:
- Check all passwords in the opened database  
![check all passwords](./images/checkAllPasswords.jpg)

- Check all passwords status indicators  
![check all passwords status bar](./images/checkAllPasswordsStatusBar.jpg)

- Check all passwords result  
![check all results](./images/checkAllResult.jpg)

- Show all entries which are pwned  
![show all pwned entries](./images/showAllPwned.jpg)

- Check the current selected entry  
![check the current selected entry](./images/checkSingleResult.jpg)

- Check the current selected entry result  
![check current selected result](./images/pwnedEntry.jpg)

- Toggle the ignore-state of a single entry  
![toggle ignore state](./images/toggleIgnoreState.jpg)

[KeePass plugin]: https://keepass.info/help/v2/plugins.html
[k-Anonymity model]: https://en.wikipedia.org/wiki/K-anonymity
[Pwned Passwords]: https://haveibeenpwned.com/API/v3#PwnedPasswords
