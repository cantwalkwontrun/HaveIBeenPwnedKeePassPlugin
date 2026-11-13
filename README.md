---
lang: en-GB
---

# Have I Been Pwned KeePass Plugin

## Maintenance fork

This maintenance fork fixes stale asynchronous results, history/editor-copy checks, HTTP error handling and breach metadata. It also retains automatic checks queued during bulk scans, preserves clean state after saving unchanged results and synchronises settings across menus. See [REVIEW.md](./REVIEW.md) for findings, verification and limitations.

Version **0.11.0** is distributed as `HaveIBeenPwnedPlugin.dll` from this fork's [releases](https://github.com/cantwalkwontrun/HaveIBeenPwnedKeePassPlugin/releases). KeePass update notifications remain intentionally disabled; check the fork releases manually. Verify the DLL with `Get-FileHash -Algorithm SHA256` against the release's `SHA256SUMS.txt`.

## Viewing affected accounts

After **Check all passwords**, the plugin displays entries tagged `pwned` in KeePass's normal entry list. Use **Tools → Have I Been Pwned → Show accounts with breached passwords** to reopen the list without another network request. Your configured Title, User Name and URL columns identify each account; double-click an entry to edit it as usual. Select a group to return to your normal view.

These are **last recorded password-check results**. Ignored, expired, changed or unchecked entries can retain an older `pwned` tag. Reopening the list refreshes its membership; a completed bulk scan also replaces it, including with an empty list when no tags remain. A password match means that the password appears in HIBP data; it does not establish that the particular account was breached. This feature adds no account or email-address lookup and sends no entry titles, usernames or URLs to HIBP.

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

#### Linux (unverified in this fork)
 - [Mono 5.18](https://www.mono-project.com/docs/about-mono/releases/5.18.0/) or higher
 - On some Linux systems, the `mono-complete` package may be required for plugins to work properly ([Details on keepass.info](https://keepass.info/help/v2/setup.html#mono))

### How to install/update
 1. Download the [latest fork release (.dll file) from GitHub](https://github.com/cantwalkwontrun/HaveIBeenPwnedKeePassPlugin/releases/latest)
 2. In KeePass, click 'Tools' → 'Plugins' → button 'Open Folder'  
    *KeePass now opens a folder called 'Plugins'*
 3. Exit KeePass and retain one currently working plugin copy locally for rollback
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
