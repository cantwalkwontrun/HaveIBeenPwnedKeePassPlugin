using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using KeePass.Plugins;
using KeePass.UI;
using KeePassLib;
using KeePassLib.Utility;

namespace HaveIBeenPwnedPlugin
{
    public sealed class HaveIBeenPwnedPluginExt : Plugin
    {
        private IPluginHost _pluginHost = null;
        private bool _checkPasswordOnEntryTouched = true;
        private bool _isIgnoreExpiredEntriesEnabled = true;
        private bool _isShowGoodNewsOnManualEntryCheckEnabled = false;
        private bool _isModifyPwEntryDatesEnabled = false;
        private const string Option_CheckPasswordOnEntryTouched = "HaveIBeenPwnedPlugin_Option_CheckPasswordOnEntryTouched";
        private const string Option_IgnoreExpiredEntries = "HaveIBeenPwnedPlugin_Option_IgnoreExpiredEntries";
        private const string Option_ShowGoodNewsOnManualEntryCheck = "HaveIBeenPwnedPlugin_Option_ShowGoodNewsOnManualEntryCheck";
        private const string Option_ModifyPwEntryDates = "HaveIBeenPwnedPlugin_Option_ModifyPwEntryDates";
        private const string BreachedTag = "pwned";
        private const string IgnorePwnedTag = "pwned-ignore";
        private const string BreachCountCustomDataName = "pwned-count";
        private const string Message_NoEntrySelected = "No entry selected!";
        private readonly HIBP _hibp;
        private readonly CancellationTokenSource _shutdown = new CancellationTokenSource();
        private readonly Dictionary<PwEntry, EntryCheckContext> _entriesBeingChecked = new Dictionary<PwEntry, EntryCheckContext>();
        private bool _isBulkCheckRunning;
        private bool _terminated;
        private bool _hasReportedHibpError;

        public HaveIBeenPwnedPluginExt() => _hibp = new HIBP();

        // This development fork has no published binaries or update manifest yet.
        public override string UpdateUrl => null;

        /// <summary>
        /// Initialization of the plugin
        /// </summary>
        /// <param name="pluginHost">Plugin host interface. Access the KeePass main window, the currently opened database, etc.</param>
        /// <returns><c>true</c> if plugin should be loaded within KeePass, otherwise <c>false</c></returns>
        public override bool Initialize(IPluginHost pluginHost)
        {
            if (pluginHost == null)
            {
                return false;
            }

            _pluginHost = pluginHost;

            InitializeCustomConfigSettings();
            InitializeEvents();

            return true;
        }

        private void InitializeEvents()
        {
            PwEntry.EntryTouched += PwEntry_TouchedAsync;
        }

        private void InitializeCustomConfigSettings()
        {
            _checkPasswordOnEntryTouched = _pluginHost.CustomConfig.GetBool(Option_CheckPasswordOnEntryTouched, true);
            _isIgnoreExpiredEntriesEnabled = _pluginHost.CustomConfig.GetBool(Option_IgnoreExpiredEntries, true);
            _isShowGoodNewsOnManualEntryCheckEnabled = _pluginHost.CustomConfig.GetBool(Option_ShowGoodNewsOnManualEntryCheck, false);
            _isModifyPwEntryDatesEnabled = _pluginHost.CustomConfig.GetBool(Option_ModifyPwEntryDates, false);
        }

        private async void PwEntry_TouchedAsync(object o, ObjectTouchedEventArgs e)
        {
            if (_terminated || !_checkPasswordOnEntryTouched || _isBulkCheckRunning)
            {
                return;
            }

            if (e.Modified && e.Object is PwEntry pwEntry)
            {
                // EntryTouched also fires for editor/history clones. Only check live entries.
                if (!new EntryCheckContext(_pluginHost.Database, pwEntry).IsCurrent(_pluginHost.Database) ||
                    CheckEntryIgnoreConditions(pwEntry) != PwEntryIgnoreState.None)
                {
                    return;
                }

                await CheckHaveIBeenPwnedForEntry(pwEntry, automatic: true);
            }
        }

        /// <summary>
        /// Checks whether the entry should be ignored or not
        /// Any other <c>PwEntryIgnoreState</c> than <c>PwEntryIgnoreState.None</c> will be ignored
        /// </summary>
        /// <param name="pwEntry">The password entry</param>
        /// <returns>The <c>PwEntryIgnoreState</c> with the ignore reason</returns>
        private PwEntryIgnoreState CheckEntryIgnoreConditions(PwEntry pwEntry)
        {
            if (_isIgnoreExpiredEntriesEnabled && pwEntry.IsExpired())
            {
                return PwEntryIgnoreState.IsExpired;
            }

            if (pwEntry.HasTag(IgnorePwnedTag) || pwEntry.HasInheritedTag(IgnorePwnedTag))
            {
                return PwEntryIgnoreState.IsIgnored;
            }

            if (pwEntry.Strings.GetSafe(PwDefs.PasswordField).IsEmpty)
            {
                return PwEntryIgnoreState.IsEmptyPassword;
            }

            return PwEntryIgnoreState.None;
        }

        private async Task CheckHaveIBeenPwnedForEntry(PwEntry pwEntry, Action executesWhenEntryIsGood = null, bool automatic = false)
        {
            if (pwEntry == null)
            {
                throw new ArgumentNullException(nameof(pwEntry));
            }

            // Don't check HIBP with an empty password
            if (pwEntry.Strings.GetSafe(PwDefs.PasswordField).IsEmpty)
            {
                return;
            }

            var context = new EntryCheckContext(_pluginHost.Database, pwEntry);
            if (_terminated || _isBulkCheckRunning || !context.IsCurrent(_pluginHost.Database)) return;
            if (_entriesBeingChecked.TryGetValue(pwEntry, out EntryCheckContext pending) && pending.IsCurrent(_pluginHost.Database)) return;
            _entriesBeingChecked[pwEntry] = context;
            try
            {
                using (SHA1 sha1 = SHA1.Create())
                {
                    var (isBreached, breachCount) = await _hibp.CheckRangeAsync(ComputeSha1HexPartsFromEntry(pwEntry, sha1), _shutdown.Token);
                    if (_terminated || !context.IsCurrent(_pluginHost.Database) ||
                        (automatic && (!_checkPasswordOnEntryTouched || CheckEntryIgnoreConditions(pwEntry) != PwEntryIgnoreState.None))) return;

                    bool entryModified = false;
                    if (isBreached)
                    {
                        entryModified = UpdateEntryWithBreachInformation(pwEntry, breachCount);
                        UpdateUI_EntryList(entryModified);

                        MessageService.ShowWarning($"Oh no. This password is breached and has been seen {breachCount} times before!",
                                                   $"Source: https://haveibeenpwned.com");
                    }
                    else
                    {
                        entryModified = UpdateEntryRemoveBreachInformation(pwEntry);
                        UpdateUI_EntryList(entryModified);
                        executesWhenEntryIsGood?.Invoke();
                    }
                }
            }
            catch (HttpRequestException)
            {
                if (!_terminated && context.IsCurrent(_pluginHost.Database)) SetHibpErrorState();
            }
            catch (OperationCanceledException)
            {
                // HttpClient timeouts also arrive as cancellation on .NET Framework.
                if (!_terminated && context.IsCurrent(_pluginHost.Database)) SetHibpErrorState();
            }
            finally
            {
                if (_entriesBeingChecked.TryGetValue(pwEntry, out EntryCheckContext current) && ReferenceEquals(current, context))
                    _entriesBeingChecked.Remove(pwEntry);
            }
        }

        private void SetHibpErrorState()
        {
            UnsubscribeEvents();
            if (_terminated || _hasReportedHibpError) return;
            _hasReportedHibpError = true;

            MessageService.ShowWarning("The HIBP password check failed (connection, timeout or invalid response).",
                                       "Automatic checks, e.g. when an entry gets modified, are disabled until you restart KeePass.",
                                       "You can still use all manual functions once connectivity is restored.");
        }

        /// <summary>
        /// Removes breach tag from entry
        /// </summary>
        /// <param name="pwEntry"></param>
        /// <returns><c>true</c>, if any breach tag has been removed, otherwise false</returns>
        private bool UpdateEntryRemoveBreachInformation(PwEntry pwEntry)
        {
            bool modified = pwEntry.RemoveTag(BreachedTag);
            if (pwEntry.CustomData.Exists(BreachCountCustomDataName))
            {
                pwEntry.CustomData.Remove(BreachCountCustomDataName);
                modified = true;
            }
            if (modified) UpdatePwEntryDates(pwEntry);
            return modified;
        }

        private void UpdatePwEntryDates(PwEntry pwEntry)
        {
            if (_isModifyPwEntryDatesEnabled)
            {
                pwEntry.LastModificationTime = DateTime.UtcNow;
                pwEntry.LastAccessTime = DateTime.UtcNow;
            }
        }

        /// <summary>
        /// Adds breach tag to entry
        /// </summary>
        /// <param name="pwEntry"></param>
        /// <param name="breachCount"></param>
        /// <returns><c>true</c>, if breach metadata has changed, otherwise <c>false</c></returns>
        private bool UpdateEntryWithBreachInformation(PwEntry pwEntry, long breachCount)
        {
            bool modified = pwEntry.AddTag(BreachedTag);
            string count = breachCount.ToString(CultureInfo.InvariantCulture);
            if (pwEntry.CustomData.Get(BreachCountCustomDataName) != count)
            {
                pwEntry.CustomData.Set(BreachCountCustomDataName, count);
                modified = true;
            }
            if (modified) UpdatePwEntryDates(pwEntry);
            return modified;
        }

        public override void Terminate()
        {
            if (_terminated) return;
            _terminated = true;
            UnsubscribeEvents();
            _shutdown.Cancel();
            if (_pluginHost != null) SaveCurrentCustomConfigSettings();
            _hibp.Dispose();
            _shutdown.Dispose();
        }

        private void UnsubscribeEvents()
        {
            PwEntry.EntryTouched -= PwEntry_TouchedAsync;
        }

        private void SaveCurrentCustomConfigSettings()
        {
            _pluginHost.CustomConfig.SetBool(Option_CheckPasswordOnEntryTouched, _checkPasswordOnEntryTouched);
            _pluginHost.CustomConfig.SetBool(Option_IgnoreExpiredEntries, _isIgnoreExpiredEntriesEnabled);
            _pluginHost.CustomConfig.SetBool(Option_ShowGoodNewsOnManualEntryCheck, _isShowGoodNewsOnManualEntryCheckEnabled);
            _pluginHost.CustomConfig.SetBool(Option_ModifyPwEntryDates, _isModifyPwEntryDatesEnabled);
        }

        public override ToolStripMenuItem GetMenuItem(PluginMenuType t)
        {
            // Don't add menu items to tray
            if (t == PluginMenuType.Tray)
            {
                return null;
            }

            ToolStripMenuItem pluginRootMenuItem = new ToolStripMenuItem("Have I Been Pwned");

            ToolStripMenuItem checkCurrentPasswordMenuItem = new ToolStripMenuItem
            {
                Text = "Check current password"
            };
            checkCurrentPasswordMenuItem.Click += CheckCurrentPasswordMenuItem_ClickAsync;
            pluginRootMenuItem.DropDownItems.Add(checkCurrentPasswordMenuItem);

            ToolStripMenuItem checkAllPasswordsMenuItem = new ToolStripMenuItem
            {
                Text = "Check all passwords"
            };
            checkAllPasswordsMenuItem.Click += CheckAllPasswordsMenuItem_ClickAsync;
            pluginRootMenuItem.DropDownItems.Add(checkAllPasswordsMenuItem);

            pluginRootMenuItem.DropDownItems.Add(new ToolStripSeparator());

            if (t == PluginMenuType.Entry)
            {
                ToolStripMenuItem toggleCurrentPasswordIgnoreStateMenuItem = new ToolStripMenuItem
                {
                    Text = "Toggle ignore state"
                };
                toggleCurrentPasswordIgnoreStateMenuItem.Click += ToggleCurrentPasswordIgnoreStateMenuItem_Click;
                pluginRootMenuItem.DropDownItems.Add(toggleCurrentPasswordIgnoreStateMenuItem);

                pluginRootMenuItem.DropDownItems.Add(new ToolStripSeparator());
            }

            ToolStripMenuItem checkBoxMenuItem_Option_CheckPasswordOnEntryTouched = new ToolStripMenuItem
            {
                Text = "Check password when entry gets modified",
                Checked = _checkPasswordOnEntryTouched
            };
            checkBoxMenuItem_Option_CheckPasswordOnEntryTouched.Click += CheckBoxMenuItem_Option_CheckPasswordOnEntryTouched_Click;
            pluginRootMenuItem.DropDownItems.Add(checkBoxMenuItem_Option_CheckPasswordOnEntryTouched);

            ToolStripMenuItem checkBoxMenuItem_Option_SkipExpiredEntries = new ToolStripMenuItem
            {
                Text = "Skip expired entries",
                Checked = _isIgnoreExpiredEntriesEnabled
            };
            checkBoxMenuItem_Option_SkipExpiredEntries.Click += CheckBoxMenuItem_Option_SkipExpiredEntries_Click;
            pluginRootMenuItem.DropDownItems.Add(checkBoxMenuItem_Option_SkipExpiredEntries);

            ToolStripMenuItem checkBoxMenuItem_Option_ShowGoodNewsOnManualEntryCheck = new ToolStripMenuItem
            {
                Text = "Show good news when checking an entry manually too",
                Checked = _isShowGoodNewsOnManualEntryCheckEnabled
            };
            checkBoxMenuItem_Option_ShowGoodNewsOnManualEntryCheck.Click += CheckBoxMenuItem_Option_ShowGoodNewsOnManualEntryCheck_Click;
            pluginRootMenuItem.DropDownItems.Add(checkBoxMenuItem_Option_ShowGoodNewsOnManualEntryCheck);

            ToolStripMenuItem checkBoxMenuItem_Option_ModifyPwEntryDates = new ToolStripMenuItem
            {
                Text = "Enable entry date changes when breach information is added/removed",
                Checked = _isModifyPwEntryDatesEnabled
            };
            checkBoxMenuItem_Option_ModifyPwEntryDates.Click += CheckBoxMenuItem_Option_ModifyPwEntryDates_Click;
            pluginRootMenuItem.DropDownItems.Add(checkBoxMenuItem_Option_ModifyPwEntryDates);

            return pluginRootMenuItem;
        }

        private void CheckBoxMenuItem_Option_ModifyPwEntryDates_Click(object sender, EventArgs e)
        {
            _isModifyPwEntryDatesEnabled = !_isModifyPwEntryDatesEnabled;
            UIUtil.SetChecked(sender as ToolStripMenuItem, _isModifyPwEntryDatesEnabled);
        }

        private void CheckBoxMenuItem_Option_ShowGoodNewsOnManualEntryCheck_Click(object sender, EventArgs e)
        {
            _isShowGoodNewsOnManualEntryCheckEnabled = !_isShowGoodNewsOnManualEntryCheckEnabled;
            UIUtil.SetChecked(sender as ToolStripMenuItem, _isShowGoodNewsOnManualEntryCheckEnabled);
        }

        private void CheckBoxMenuItem_Option_SkipExpiredEntries_Click(object sender, EventArgs e)
        {
            _isIgnoreExpiredEntriesEnabled = !_isIgnoreExpiredEntriesEnabled;
            UIUtil.SetChecked(sender as ToolStripMenuItem, _isIgnoreExpiredEntriesEnabled);
        }

        private async void CheckCurrentPasswordMenuItem_ClickAsync(object sender, EventArgs e)
        {
            if (TryGetCurrentSelectedPwEntry(out PwEntry selectedEntry))
            {
                await CheckHaveIBeenPwnedForEntry(selectedEntry, () =>
                {
                    if (_isShowGoodNewsOnManualEntryCheckEnabled)
                    {
                        MessageService.ShowInfoEx("Good news", $"No pwnage found!",
                                                               $"Source: https://haveibeenpwned.com");
                    }
                });
            }
            else
            {
                MessageService.ShowInfo(Message_NoEntrySelected);
            }
        }

        private void ToggleCurrentPasswordIgnoreStateMenuItem_Click(object sender, EventArgs e)
        {
            if (TryGetCurrentSelectedPwEntry(out PwEntry selectedEntry))
            {
                if (selectedEntry.HasTag(IgnorePwnedTag))
                {
                    selectedEntry.RemoveTag(IgnorePwnedTag);
                }
                else
                {
                    selectedEntry.AddTag(IgnorePwnedTag);
                }

                UpdateUI_EntryList(true);
            }
            else
            {
                MessageService.ShowInfo(Message_NoEntrySelected);
            }
        }

        private bool TryGetCurrentSelectedPwEntry(out PwEntry currentSelectedPwEntry)
        {
            currentSelectedPwEntry = null;

            if (IsDatabaseOpen())
            {
                currentSelectedPwEntry = _pluginHost.MainWindow.GetSelectedEntry(true, false);

                if (currentSelectedPwEntry != null)
                {
                    return true;
                }
            }

            return false;
        }

        private async void CheckAllPasswordsMenuItem_ClickAsync(object sender, EventArgs e)
        {
            if (_terminated || _isBulkCheckRunning || _entriesBeingChecked.Count > 0 || !IsDatabaseOpen()) return;

            var messages = await CheckAllPasswordsAsync(_pluginHost.Database, _pluginHost.MainWindow.CreateStatusBarLogger());
            if (!_terminated) MessageService.ShowInfo(messages);
        }

        private async Task<string[]> CheckAllPasswordsAsync(PwDatabase database, KeePassLib.Interfaces.IStatusLogger statusBarLogger)
        {
            var rootGroup = database.RootGroup;
            var entries = rootGroup.GetEntries(true).ToList();
            int skippedExpiredEntriesCount = 0;
            int skippedIgnoredEntriesCount = 0;
            int skippedEmptyPasswordEntriesCount = 0;
            int skippedChangedEntriesCount = 0;
            int checkedEntriesCount = 0;
            int pwnedEntriesCount = 0;
            int addedPwnedTagCount = 0;
            int removedPwnedTagCount = 0;
            bool modified = false;
            bool interrupted = false;
            _isBulkCheckRunning = true;
            try
            {
                statusBarLogger.StartLogging("Checking passwords against HIBP...", false);
                using (SHA1 sha1 = SHA1.Create())
                {
                    for (int i = 0; i < entries.Count; i++)
                    {
                        if (_terminated || !database.IsOpen || !ReferenceEquals(database, _pluginHost.Database) ||
                            !ReferenceEquals(rootGroup, database.RootGroup))
                        {
                            interrupted = true;
                            break;
                        }
                        PwEntry entry = entries[i];
                        var context = new EntryCheckContext(database, entry);
                        var ignoreState = CheckEntryIgnoreConditions(entry);
                        if (ignoreState == PwEntryIgnoreState.IsExpired) skippedExpiredEntriesCount++;
                        else if (ignoreState == PwEntryIgnoreState.IsIgnored) skippedIgnoredEntriesCount++;
                        else if (ignoreState == PwEntryIgnoreState.IsEmptyPassword) skippedEmptyPasswordEntriesCount++;
                        else if (!context.IsCurrent(_pluginHost.Database)) skippedChangedEntriesCount++;
                        else
                        {
                            var result = await _hibp.CheckRangeAsync(ComputeSha1HexPartsFromEntry(entry, sha1), _shutdown.Token);
                            if (_terminated || !database.IsOpen || !ReferenceEquals(database, _pluginHost.Database) ||
                                !ReferenceEquals(rootGroup, database.RootGroup))
                            {
                                interrupted = true;
                                break;
                            }
                            if (!context.IsCurrent(_pluginHost.Database) || CheckEntryIgnoreConditions(entry) != PwEntryIgnoreState.None)
                            {
                                skippedChangedEntriesCount++;
                            }
                            else
                            {
                                checkedEntriesCount++;
                                bool wasTagged = entry.HasTag(BreachedTag);
                                if (result.isBreached)
                                {
                                    modified |= UpdateEntryWithBreachInformation(entry, result.breachCount);
                                    if (!wasTagged) addedPwnedTagCount++;
                                    pwnedEntriesCount++;
                                }
                                else
                                {
                                    modified |= UpdateEntryRemoveBreachInformation(entry);
                                    if (wasTagged) removedPwnedTagCount++;
                                }
                                // Mark this database dirty before the next await (it may be saved or locked).
                                if (modified) database.Modified = true;
                            }
                        }
                        if (_terminated) break;
                        statusBarLogger.SetText($"Checking passwords against HIBP... {i + 1}/{entries.Count}", KeePassLib.Interfaces.LogStatusType.Info);
                        statusBarLogger.SetProgress((uint)((i + 1) * 100L / entries.Count));
                    }
                }
            }
            catch (HttpRequestException)
            {
                interrupted = true;
                SetHibpErrorState();
            }
            catch (OperationCanceledException)
            {
                interrupted = true;
                if (!_terminated) SetHibpErrorState();
            }
            finally
            {
                statusBarLogger.EndLogging();
                _isBulkCheckRunning = false;
            }

            if (_terminated) return new string[0];
            if (ReferenceEquals(database, _pluginHost.Database) && database.IsOpen && ReferenceEquals(rootGroup, database.RootGroup))
                UpdateUI_EntryList(false);
            return new[] { interrupted ? "Password check incomplete." : "Password check completed.",
                                    $"Checked entries: {checkedEntriesCount}",
                                    $"Pwned entries: {pwnedEntriesCount}",
                                    $"New pwned entries: {addedPwnedTagCount}",
                                    $"Entries not pwned anymore: {removedPwnedTagCount}",
                                    $"Skipped expired entries: {skippedExpiredEntriesCount}",
                                    $"Skipped ignored entries: {skippedIgnoredEntriesCount}",
                                    $"Skipped entries with empty passwords: {skippedEmptyPasswordEntriesCount}",
                                    $"Skipped changed or unavailable entries: {skippedChangedEntriesCount}" };
        }

        private void UpdateUI_EntryList(bool setModified)
        {
            // Quote from KeePass.Forms.MainForm.UpdateEntryList
            // > Note that if you only made small changes (like editing an existing entry), the
            // > RefreshEntriesList function could be a better choice, as it only
            // > updates currently listed items and doesn't rebuild the whole list as
            // > UpdateEntryList.
            if (setModified && IsDatabaseOpen())
            {
                _pluginHost.Database.Modified = true;
            }
            _pluginHost.MainWindow?.RefreshEntriesList();
        }

        private (string sha1Prefix, string sha1Suffix) ComputeSha1HexPartsFromEntry(PwEntry entry, SHA1 sha1)
        {
            byte[] passwordBytes = entry.Strings.GetSafe(PwDefs.PasswordField).ReadUtf8();
            try
            {
                string sha1Hex = BitConverter.ToString(sha1.ComputeHash(passwordBytes)).Replace("-", string.Empty);
                return (sha1Hex.Substring(0, 5), sha1Hex.Substring(5));
            }
            finally
            {
                MemUtil.ZeroByteArray(passwordBytes);
            }
        }

        private void CheckBoxMenuItem_Option_CheckPasswordOnEntryTouched_Click(object sender, EventArgs e)
        {
            _checkPasswordOnEntryTouched = !_checkPasswordOnEntryTouched;
            UIUtil.SetChecked(sender as ToolStripMenuItem, _checkPasswordOnEntryTouched);
        }

        private bool IsDatabaseOpen()
        {
            PwDatabase database = _pluginHost.Database;

            if (database != null && database.IsOpen)
            {
                return true;
            }

            return false;
        }
    }
}
