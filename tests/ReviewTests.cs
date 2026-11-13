using System;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using HaveIBeenPwnedPlugin;
using KeePass.Plugins;
using KeePassLib;
using KeePassLib.Security;

internal static partial class Program
{
    private static void RunReviewTests()
    {
        Run("settings stay synchronised across all menu copies", () => ReviewFixture((plugin, host, context) =>
        {
            using (var main = plugin.GetMenuItem(PluginMenuType.Main))
            using (var entry = plugin.GetMenuItem(PluginMenuType.Entry))
            {
                var source = (ToolStripMenuItem)main.DropDownItems["HaveIBeenPwnedPlugin_Option_IgnoreExpiredEntries"];
                var copy = (ToolStripMenuItem)entry.DropDownItems[source.Name];
                Assert(source.Checked && copy.Checked);
                source.PerformClick(); Assert(!source.Checked && !copy.Checked);
                copy.PerformClick(); Assert(source.Checked && copy.Checked);
                Set(plugin, "_isBulkCheckRunning", true); Invoke(plugin, "RefreshMenus");
                Assert(!main.DropDownItems["CheckAll"].Enabled && !entry.DropDownItems["CheckCurrent"].Enabled);
                Set(plugin, "_isBulkCheckRunning", false); Invoke(plugin, "RefreshMenus");
                Assert(main.DropDownItems["CheckAll"].Enabled && entry.DropDownItems["CheckCurrent"].Enabled);
            }
        }));
        Run("every failed manual check reports failure after an automatic outage", () =>
        {
            var previous = SynchronizationContext.Current; var context = new PumpContext(); SynchronizationContext.SetSynchronizationContext(context);
            var host = new FakeHost { Database = Database() }; var entry = Entry(); host.Database.RootGroup.AddEntry(entry, true);
            var plugin = Plugin(host, new FakeHandler((r, t) => Task.FromResult(Response("invalid"))));
            int warnings = 0; Set(plugin, "_showWarning", (Action<string[]>)(messages => warnings++));
            try
            {
                Invoke(plugin, "SetHibpErrorState", true);
                for (int i = 0; i < 2; i++) { Task task = CheckEntry(plugin, entry, null, false); context.Until(() => task.IsCompleted); task.GetAwaiter().GetResult(); }
                Assert(warnings == 3);
            }
            finally { plugin.Terminate(); host.Database.Close(); SynchronizationContext.SetSynchronizationContext(previous); }
        });
        Run("an oversized range response fails without clearing breach information", () =>
        {
            var previous = SynchronizationContext.Current; var context = new PumpContext(); SynchronizationContext.SetSynchronizationContext(context);
            var host = new FakeHost { Database = Database() }; var entry = Entry(); host.Database.RootGroup.AddEntry(entry, true);
            entry.AddTag("pwned"); entry.CustomData.Set("pwned-count", "3");
            var plugin = Plugin(host, new FakeHandler((r, t) => Task.FromResult(Response(new string('F', 2 * 1024 * 1024 + 1)))));
            int warnings = 0; Set(plugin, "_showWarning", (Action<string[]>)(messages => warnings++));
            try
            {
                Task task = CheckEntry(plugin, entry, null, false); context.Until(() => task.IsCompleted); task.GetAwaiter().GetResult();
                Assert(warnings == 1 && entry.HasTag("pwned") && entry.CustomData.Get("pwned-count") == "3");
            }
            finally { plugin.Terminate(); host.Database.Close(); SynchronizationContext.SetSynchronizationContext(previous); }
        });
        foreach (bool changedPassword in new[] { false, true })
        {
            bool captured = changedPassword;
            Run(changedPassword ? "password edited during bulk scan is rechecked" : "a save during bulk is not dirtied by unchanged results", () => BulkReentrancy(captured));
        }
    }

    private static void ReviewFixture(Action<HaveIBeenPwnedPluginExt, FakeHost, PumpContext> test)
    {
        var previous = SynchronizationContext.Current; var context = new PumpContext(); SynchronizationContext.SetSynchronizationContext(context);
        var host = new FakeHost { Database = Database() };
        var plugin = Plugin(host, new FakeHandler((r, t) => Task.FromResult(Response(new string('F', 35) + ":1"))));
        try { test(plugin, host, context); }
        finally { plugin.Terminate(); host.Database.Close(); SynchronizationContext.SetSynchronizationContext(previous); }
    }

    private static void BulkReentrancy(bool edit)
    {
        var previous = SynchronizationContext.Current; var context = new PumpContext(); SynchronizationContext.SetSynchronizationContext(context);
        var host = new FakeHost { Database = Database() }; var first = Entry(); var second = Entry();
        first.AddTag("pwned"); first.CustomData.Set("pwned-count", "3");
        host.Database.RootGroup.AddEntry(first, true); host.Database.RootGroup.AddEntry(second, true);
        int requests = 0; var pending = new TaskCompletionSource<HttpResponseMessage>();
        var plugin = Plugin(host, new FakeHandler((r, t) => { requests++; return requests == 2 ? pending.Task : Task.FromResult(Response(new string('F', 35) + ":1")); }));
        try
        {
            var task = (Task<string[]>)Invoke(plugin, "CheckAllPasswordsAsync", host.Database, new FakeLogger());
            context.Until(() => requests == 2);
            Assert(host.Database.Modified && !first.HasTag("pwned"));
            host.Database.Modified = false; // Model a save while the next network request is pending.
            if (edit)
            {
                first.Strings.Set(PwDefs.PasswordField, new ProtectedString(true, "changed-synthetic-password"));
                first.Touch(true);
            }
            pending.SetResult(Response(new string('F', 35) + ":1"));
            context.Until(() => task.IsCompleted); task.GetAwaiter().GetResult();
            Assert(requests == (edit ? 3 : 2));
            Assert(!host.Database.Modified);
        }
        finally { plugin.Terminate(); pending.TrySetCanceled(); context.Drain(); host.Database.Close(); SynchronizationContext.SetSynchronizationContext(previous); }
    }
}
