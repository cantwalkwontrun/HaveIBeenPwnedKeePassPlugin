using System;
using System.Collections.Generic;
using System.ComponentModel;
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
        private bool _automaticChecksSuspended;
        private readonly Dictionary<PwEntry, EntryCheckContext> _pendingAutomaticChecks = new Dictionary<PwEntry, EntryCheckContext>();
        private readonly List<ToolStripMenuItem> _menus = new List<ToolStripMenuItem>();
        private Action<string[]> _showWarning = messages => MessageService.ShowWarning(messages);
        private SynchronizationContext _uiContext;
        private int _uiThreadId;

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
            _uiThreadId = Thread.CurrentThread.ManagedThreadId;
            _uiContext = SynchronizationContext.Current;
            if (_uiContext == null && pluginHost.MainWindow != null)
                _uiContext = new WindowsFormsSynchronizationContext();

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
            if (_terminated) return;
            // Other plugins can touch entries from worker threads. Keep database access,
            // request bookkeeping and WinForms continuations on KeePass's UI thread.
            if (Thread.CurrentThread.ManagedThreadId != _uiThreadId)
            {
                try { _uiContext?.Post(_ => PwEntry_TouchedAsync(o, e), null); }
                catch (InvalidAsynchronousStateException) { } // UI thread has exited.
                catch (InvalidOperationException) { } // Dispatch control has closed.
                return;
            }

            if (_terminated || !_checkPasswordOnEntryTouched || _automaticChecksSuspended)
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

                if (_isBulkCheckRunning)
                {
                    _pendingAutomaticChecks[pwEntry] = new EntryCheckContext(_pluginHost.Database, pwEntry);
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
            RefreshMenus();
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

                        _showWarning(new[] { $"This password appears in breach data {breachCount} times.", "Source: https://haveibeenpwned.com" });
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
                if (!_terminated && context.IsCurrent(_pluginHost.Database)) SetHibpErrorState(automatic);
            }
            catch (OperationCanceledException)
            {
                // HttpClient timeouts also arrive as cancellation on .NET Framework.
                if (!_terminated && context.IsCurrent(_pluginHost.Database)) SetHibpErrorState(automatic);
            }
            finally
            {
                if (_entriesBeingChecked.TryGetValue(pwEntry, out EntryCheckContext current) && ReferenceEquals(current, context))
                    _entriesBeingChecked.Remove(pwEntry);
                RefreshMenus();
            }
        }

        private void SetHibpErrorState(bool automatic = true)
        {
            UnsubscribeEvents();
            _automaticChecksSuspended = true;
            _pendingAutomaticChecks.Clear();
            if (_terminated || (automatic && _hasReportedHibpError)) return;
            _hasReportedHibpError = true;
            _showWarning(new[] { "The HIBP password check failed (connection, timeout or invalid response).",
                "No clean result was obtained. Existing breach information has been preserved.",
                "Automatic checks are disabled until KeePass restarts. Manual checks remain available." });
        }

        private async Task DrainPendingAutomaticChecksAsync()
        {
            var pending = _pendingAutomaticChecks.ToArray();
            _pendingAutomaticChecks.Clear();
            foreach (var item in pending)
            {
                if (_terminated || _automaticChecksSuspended || !_checkPasswordOnEntryTouched) break;
                if (item.Value.IsCurrent(_pluginHost.Database) && CheckEntryIgnoreConditions(item.Key) == PwEntryIgnoreState.None)
                    await CheckHaveIBeenPwnedForEntry(item.Key, automatic: true);
            }
        }

        private void RefreshMenus()
        {
            _menus.RemoveAll(menu => menu.IsDisposed);
            bool busy = _isBulkCheckRunning || _entriesBeingChecked.Count > 0;
            foreach (var menu in _menus)
            {
                foreach (ToolStripItem item in menu.DropDownItems)
                {
                    var option = item as ToolStripMenuItem;
                    if (option == null) continue;
                    if (option.Name == Option_CheckPasswordOnEntryTouched)
                    {
                        option.Checked = _checkPasswordOnEntryTouched;
                        option.Text = _automaticChecksSuspended ? "Automatic checks paused until restart" : "Check modified entries automatically";
                    }
                    else if (option.Name == Option_IgnoreExpiredEntries) option.Checked = _isIgnoreExpiredEntriesEnabled;
                    else if (option.Name == Option_ShowGoodNewsOnManualEntryCheck) option.Checked = _isShowGoodNewsOnManualEntryCheckEnabled;
                    else if (option.Name == Option_ModifyPwEntryDates) option.Checked = _isModifyPwEntryDatesEnabled;
                    else if (option.Name == "CheckCurrent" || option.Name == "CheckAll")
                        option.Enabled = !_terminated && !busy && _pluginHost != null && IsDatabaseOpen();
                }
            }
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
            _pendingAutomaticChecks.Clear();
            RefreshMenus();
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
                Name = "CheckCurrent",
                Text = "Check current password"
            };
            checkCurrentPasswordMenuItem.Click += CheckCurrentPasswordMenuItem_ClickAsync;
            pluginRootMenuItem.DropDownItems.Add(checkCurrentPasswordMenuItem);

            ToolStripMenuItem checkAllPasswordsMenuItem = new ToolStripMenuItem
            {
                Name = "CheckAll",
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
                Name = Option_CheckPasswordOnEntryTouched,
                Text = "Check modified entries automatically",
                Checked = _checkPasswordOnEntryTouched
            };
            checkBoxMenuItem_Option_CheckPasswordOnEntryTouched.Click += CheckBoxMenuItem_Option_CheckPasswordOnEntryTouched_Click;
            pluginRootMenuItem.DropDownItems.Add(checkBoxMenuItem_Option_CheckPasswordOnEntryTouched);

            ToolStripMenuItem checkBoxMenuItem_Option_SkipExpiredEntries = new ToolStripMenuItem
            {
                Name = Option_IgnoreExpiredEntries,
                Text = "Skip expired entries",
                Checked = _isIgnoreExpiredEntriesEnabled
            };
            checkBoxMenuItem_Option_SkipExpiredEntries.Click += CheckBoxMenuItem_Option_SkipExpiredEntries_Click;
            pluginRootMenuItem.DropDownItems.Add(checkBoxMenuItem_Option_SkipExpiredEntries);

            ToolStripMenuItem checkBoxMenuItem_Option_ShowGoodNewsOnManualEntryCheck = new ToolStripMenuItem
            {
                Name = Option_ShowGoodNewsOnManualEntryCheck,
                Text = "Show confirmation when no breach is found",
                Checked = _isShowGoodNewsOnManualEntryCheckEnabled
            };
            checkBoxMenuItem_Option_ShowGoodNewsOnManualEntryCheck.Click += CheckBoxMenuItem_Option_ShowGoodNewsOnManualEntryCheck_Click;
            pluginRootMenuItem.DropDownItems.Add(checkBoxMenuItem_Option_ShowGoodNewsOnManualEntryCheck);

            ToolStripMenuItem checkBoxMenuItem_Option_ModifyPwEntryDates = new ToolStripMenuItem
            {
                Name = Option_ModifyPwEntryDates,
                Text = "Update entry timestamps when breach information changes",
                Checked = _isModifyPwEntryDatesEnabled
            };
            checkBoxMenuItem_Option_ModifyPwEntryDates.Click += CheckBoxMenuItem_Option_ModifyPwEntryDates_Click;
            pluginRootMenuItem.DropDownItems.Add(checkBoxMenuItem_Option_ModifyPwEntryDates);

            _menus.Add(pluginRootMenuItem);
            pluginRootMenuItem.DropDownOpening += (sender, args) => RefreshMenus();
            RefreshMenus();
            return pluginRootMenuItem;
        }

        private void CheckBoxMenuItem_Option_ModifyPwEntryDates_Click(object sender, EventArgs e)
        {
            _isModifyPwEntryDatesEnabled = !_isModifyPwEntryDatesEnabled;
            UIUtil.SetChecked(sender as ToolStripMenuItem, _isModifyPwEntryDatesEnabled);
            RefreshMenus();
        }

        private void CheckBoxMenuItem_Option_ShowGoodNewsOnManualEntryCheck_Click(object sender, EventArgs e)
        {
            _isShowGoodNewsOnManualEntryCheckEnabled = !_isShowGoodNewsOnManualEntryCheckEnabled;
            UIUtil.SetChecked(sender as ToolStripMenuItem, _isShowGoodNewsOnManualEntryCheckEnabled);
            RefreshMenus();
        }

        private void CheckBoxMenuItem_Option_SkipExpiredEntries_Click(object sender, EventArgs e)
        {
            _isIgnoreExpiredEntriesEnabled = !_isIgnoreExpiredEntriesEnabled;
            UIUtil.SetChecked(sender as ToolStripMenuItem, _isIgnoreExpiredEntriesEnabled);
            RefreshMenus();
        }

        private async void CheckCurrentPasswordMenuItem_ClickAsync(object sender, EventArgs e)
        {
            if (TryGetCurrentSelectedPwEntry(out PwEntry selectedEntry))
            {
                await CheckHaveIBeenPwnedForEntry(selectedEntry, () =>
                {
                    if (_isShowGoodNewsOnManualEntryCheckEnabled)
                    {
                        MessageService.ShowInfoEx("No breach found", $"This password was not found in HIBP breach data.",
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
            RefreshMenus();
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
                                bool entryModified;
                                if (result.isBreached)
                                {
                                    entryModified = UpdateEntryWithBreachInformation(entry, result.breachCount);
                                    if (!wasTagged) addedPwnedTagCount++;
                                    pwnedEntriesCount++;
                                }
                                else
                                {
                                    entryModified = UpdateEntryRemoveBreachInformation(entry);
                                    if (wasTagged) removedPwnedTagCount++;
                                }
                                // Mark this database dirty before the next await (it may be saved or locked).
                                modified |= entryModified;
                                if (entryModified) database.Modified = true;
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
                try { statusBarLogger.EndLogging(); }
                finally { _isBulkCheckRunning = false; RefreshMenus(); }
                await DrainPendingAutomaticChecksAsync();
            }

            if (_terminated) return new string[0];
            if (ReferenceEquals(database, _pluginHost.Database) && database.IsOpen && ReferenceEquals(rootGroup, database.RootGroup))
                UpdateUI_EntryList(false, modified);
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

        private void UpdateUI_EntryList(bool setModified, bool refreshDetails = false)
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
            // Detail panels may paint live tags without observing date changes.
            // Repaint child controls while preserving entry dates and selection.
            if (setModified || refreshDetails) _pluginHost.MainWindow?.Invalidate(true);
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
            RefreshMenus();
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
