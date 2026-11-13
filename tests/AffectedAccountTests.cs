using System;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using KeePass.Plugins;
using KeePassLib;
using KeePassLib.Security;

internal static partial class Program
{
    private static void RunAffectedAccountTests()
    {
        Run("affected account menu shows live entries without moving, copying or sending them", () => ReviewFixture((plugin, host, context) =>
        {
            var root = host.Database.RootGroup;
            var child = new PwGroup(true, true, "Synthetic group", PwIcon.Folder);
            root.AddGroup(child, true);
            var affected = Entry(); affected.AddTag("pwned");
            affected.Strings.Set(PwDefs.TitleField, new ProtectedString(false, "Synthetic account"));
            affected.Strings.Set(PwDefs.UserNameField, new ProtectedString(false, "synthetic@example.invalid"));
            affected.Strings.Set(PwDefs.UrlField, new ProtectedString(false, "https://example.invalid"));
            child.AddEntry(affected, true); root.AddEntry(Entry(), true);
            var orphan = Entry(); orphan.CustomData.Set("pwned-count", "9"); root.AddEntry(orphan, true);
            var password = affected.Strings.GetSafe(PwDefs.PasswordField);
            PwGroup shown = null; Set(plugin, "_displayEntryGroup", (Action<PwGroup>)(group => shown = group));
            using (var menu = plugin.GetMenuItem(PluginMenuType.Main))
                ((ToolStripMenuItem)menu.DropDownItems["ShowAffectedAccounts"]).PerformClick();
            Assert(shown != null && shown.IsVirtual && shown.Entries.UCount == 1);
            Assert(ReferenceEquals(shown.Entries.GetAt(0), affected) && ReferenceEquals(affected.ParentGroup, child));
            Assert(root.Groups.UCount == 1 && shown.ParentGroup == null && !host.Database.Modified);
            Assert(ReferenceEquals(password, affected.Strings.GetSafe(PwDefs.PasswordField)));
            Assert(shown.Notes.Contains("older results") && shown.Notes.Contains("does not establish"));
            Assert(shown.Entries.GetAt(0).Strings.ReadSafe(PwDefs.UserNameField) == "synthetic@example.invalid");
        }));

        Run("reopening affected accounts refreshes membership without a network request", () =>
        {
            var previous = SynchronizationContext.Current; SynchronizationContext.SetSynchronizationContext(new PumpContext());
            var host = new FakeHost { Database = Database() }; int requests = 0, displays = 0;
            var plugin = Plugin(host, new FakeHandler((r, t) => { requests++; throw new Exception("Viewing must not contact HIBP"); }));
            PwGroup shown = null; Set(plugin, "_displayEntryGroup", (Action<PwGroup>)(g => { shown = g; displays++; }));
            var entry = Entry(); entry.AddTag("pwned"); host.Database.RootGroup.AddEntry(entry, true);
            try
            {
                using (var menu = plugin.GetMenuItem(PluginMenuType.Entry))
                {
                    var item = (ToolStripMenuItem)menu.DropDownItems["ShowAffectedAccounts"];
                    item.PerformClick(); Assert(shown.Entries.UCount == 1);
                    entry.RemoveTag("pwned"); item.PerformClick();
                    Assert(shown.Entries.UCount == 0 && displays == 2 && requests == 0);
                }
            }
            finally { plugin.Terminate(); host.Database.Close(); SynchronizationContext.SetSynchronizationContext(previous); }
        });

        foreach (string scenario in new[] { "locked", "switched", "root replaced", "terminated" })
        {
            string captured = scenario;
            Run("affected account view rejects " + scenario + " database", () => ReviewFixture((plugin, host, context) =>
            {
                var original = host.Database; var root = original.RootGroup; var entry = Entry();
                entry.AddTag("pwned"); root.AddEntry(entry, true);
                int displays = 0; Set(plugin, "_displayEntryGroup", (Action<PwGroup>)(group => displays++));
                try
                {
                    if (captured == "locked") original.Close();
                    if (captured == "switched") host.Database = Database();
                    if (captured == "root replaced") original.RootGroup = new PwGroup(true, true);
                    if (captured == "terminated") plugin.Terminate();
                    Assert(!(bool)Invoke(plugin, "ShowAffectedAccounts", original, root) && displays == 0);
                }
                finally { if (!ReferenceEquals(original, host.Database)) original.Close(); }
            }));
        }

        Run("affected account menu follows busy, lock and shutdown state", () => ReviewFixture((plugin, host, context) =>
        {
            using (var menu = plugin.GetMenuItem(PluginMenuType.Main))
            {
                var item = menu.DropDownItems["ShowAffectedAccounts"]; Assert(item.Enabled);
                Set(plugin, "_isBulkCheckRunning", true); Invoke(plugin, "RefreshMenus"); Assert(!item.Enabled);
                Set(plugin, "_isBulkCheckRunning", false); Invoke(plugin, "RefreshMenus"); Assert(item.Enabled);
                host.Database.Close(); Invoke(plugin, "RefreshMenus"); Assert(!item.Enabled);
                plugin.Terminate(); Assert(!item.Enabled);
            }
        }));

        foreach (bool breached in new[] { true, false })
        {
            bool captured = breached;
            Run(breached ? "bulk scan opens all affected accounts including shared passwords" : "clean bulk scan replaces previous affected accounts with empty results", () =>
            {
                var previous = SynchronizationContext.Current; var context = new PumpContext(); SynchronizationContext.SetSynchronizationContext(context);
                var host = new FakeHost { Database = Database() }; var first = Entry(); var second = Entry();
                host.Database.RootGroup.AddEntry(first, true); host.Database.RootGroup.AddEntry(second, true);
                var clean = Entry(); clean.Strings.Set(PwDefs.PasswordField, new ProtectedString(true, "different-synthetic-password"));
                host.Database.RootGroup.AddEntry(clean, true);
                bool responseBreached = captured;
                int requests = 0; var plugin = Plugin(host, new FakeHandler((r, t) =>
                {
                    requests++;
                    // SHA-1 suffix of the synthetic password supplied by Entry().
                    return Task.FromResult(Response(responseBreached && requests <= 2 ? "D31DB670E4BF871404E8C524DEFE5E3B917:17" : new string('F', 35) + ":1"));
                }));
                PwGroup shown = null; Set(plugin, "_displayEntryGroup", (Action<PwGroup>)(g => shown = g));
                try
                {
                    if (!captured)
                    {
                        responseBreached = true;
                        var firstScan = (Task<string[]>)Invoke(plugin, "CheckAllPasswordsAsync", host.Database, new FakeLogger());
                        context.Until(() => firstScan.IsCompleted); firstScan.GetAwaiter().GetResult();
                        Assert(shown != null && shown.Entries.UCount == 2);
                        responseBreached = false; requests = 0;
                    }
                    var task = (Task<string[]>)Invoke(plugin, "CheckAllPasswordsAsync", host.Database, new FakeLogger());
                    context.Until(() => task.IsCompleted); var summary = task.GetAwaiter().GetResult();
                    Assert(requests == 3);
                    if (captured)
                    {
                        Assert(shown != null && shown.Entries.UCount == 2);
                        Assert(ReferenceEquals(shown.Entries.GetAt(0), first) && ReferenceEquals(shown.Entries.GetAt(1), second));
                        Assert(Array.IndexOf(summary, "Pwned entries: 2") >= 0);
                    }
                    else Assert(shown != null && shown.Entries.UCount == 0 && !first.HasTag("pwned"));
                }
                finally { plugin.Terminate(); host.Database.Close(); SynchronizationContext.SetSynchronizationContext(previous); }
            });
        }

        Run("skipped accounts retain explicitly labelled last recorded results", () => ReviewFixture((plugin, host, context) =>
        {
            var entry = Entry(); entry.AddTag("pwned"); entry.AddTag("pwned-ignore");
            host.Database.RootGroup.AddEntry(entry, true);
            PwGroup shown = null; Set(plugin, "_displayEntryGroup", (Action<PwGroup>)(g => shown = g));
            var task = (Task<string[]>)Invoke(plugin, "CheckAllPasswordsAsync", host.Database, new FakeLogger());
            context.Until(() => task.IsCompleted); var summary = task.GetAwaiter().GetResult();
            Assert(Array.IndexOf(summary, "Checked entries: 0") >= 0 && Array.IndexOf(summary, "Pwned entries: 0") >= 0);
            Assert(shown != null && shown.Entries.UCount == 1 && shown.Name.Contains("last recorded results"));
            Assert(!host.Database.Modified);
        }));
    }
}
