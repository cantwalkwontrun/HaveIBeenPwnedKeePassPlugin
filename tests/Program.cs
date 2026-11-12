using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Resources;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using HaveIBeenPwnedPlugin;
using KeePass.App.Configuration;
using KeePass.DataExchange;
using KeePass.Ecas;
using KeePass.Forms;
using KeePass.Plugins;
using KeePass.UI;
using KeePass.Util;
using KeePassLib;
using KeePassLib.Cryptography.Cipher;
using KeePassLib.Cryptography.PasswordGenerator;
using KeePassLib.Keys;
using KeePassLib.Security;
using KeePassLib.Serialization;

internal static partial class Program
{
    private const string Suffix = "0018A45C4D1DEF81644B54AB7F969B88D65";
    private const BindingFlags Private = BindingFlags.Instance | BindingFlags.NonPublic;
    private static int _passed, _failed;

    [STAThread]
    private static void Main(string[] args)
    {
        Run("CRLF response", () => CheckResponse(Suffix + ":42\r\n", true, 42));
        Run("LF response, matching second row", () => CheckResponse(new string('F', 35) + ":1\n" + Suffix + ":42\n", true, 42));
        Run("case-insensitive suffix", () => CheckResponse(Suffix.ToLowerInvariant() + ":7", true, 7));
        Run("padding is not a breach", () => CheckResponse(Suffix + ":0", false, 0));
        Run("absent suffix", () => CheckResponse(new string('F', 35) + ":3", false, 0));
        Run("large breach count", () => CheckResponse(Suffix + ":3000000000", true, 3000000000));
        foreach (string body in new[] { "", "<html>error</html>", Suffix + ":bad", Suffix + ":-1", Suffix + ":9223372036854775808", Suffix + "0:1", Suffix + ":1\ninvalid" })
        {
            string captured = body;
            Run("invalid response rejected: " + (body.Length == 0 ? "empty" : body), () => Throws<HttpRequestException>(() => Query(captured)));
        }
        Run("only five-character prefix sent, padding enabled", () =>
        {
            var handler = new FakeHandler((request, token) =>
            {
                Assert(request.RequestUri.AbsoluteUri == "https://api.pwnedpasswords.com/range/21BD1");
                Assert(string.Equals(string.Join(",", request.Headers.GetValues("Add-Padding")), "true", StringComparison.OrdinalIgnoreCase));
                Assert(request.Headers.Contains("User-Agent"));
                return Task.FromResult(Response(Suffix + ":1"));
            });
            using (var hibp = NewClient(handler)) Check(hibp).GetAwaiter().GetResult();
        });
        foreach (HttpStatusCode code in new[] { HttpStatusCode.Redirect, HttpStatusCode.NotFound, (HttpStatusCode)429, HttpStatusCode.ServiceUnavailable })
        {
            HttpStatusCode captured = code;
            Run("HTTP error rejected: " + code, () =>
            {
                using (var hibp = NewClient(new FakeHandler((r, t) => Task.FromResult(new HttpResponseMessage(captured)))))
                    Throws<HttpRequestException>(() => Check(hibp).GetAwaiter().GetResult());
            });
        }
        Run("separate plugin clients survive disposal", () =>
        {
            using (var first = NewClient(new FakeHandler((r, t) => Task.FromResult(Response(Suffix + ":1")))))
            using (var second = NewClient(new FakeHandler((r, t) => Task.FromResult(Response(Suffix + ":1")))))
            {
                first.Dispose();
                Check(second).GetAwaiter().GetResult();
            }
        });
        Run("HTTP timeout is cancellable", () =>
        {
            var client = new HttpClient(new FakeHandler(async (r, token) => { await Task.Delay(Timeout.Infinite, token); return Response(""); }));
            using (var hibp = NewClient(client))
            {
                client.Timeout = TimeSpan.FromMilliseconds(50);
                Throws<OperationCanceledException>(() => Check(hibp).GetAwaiter().GetResult());
            }
        });
        Run("updated count on already tagged entry", () =>
        {
            var plugin = new HaveIBeenPwnedPluginExt();
            try
            {
                var entry = Entry(); entry.AddTag("pwned"); entry.CustomData.Set("pwned-count", "1");
                Assert((bool)InvokeCount(plugin, entry, 2));
                Assert(entry.CustomData.Get("pwned-count") == "2");
                Assert(!(bool)InvokeCount(plugin, entry, 2));
            }
            finally { DisposePlugin(plugin); }
        });
        Run("orphaned count removed", () =>
        {
            var plugin = new HaveIBeenPwnedPluginExt();
            try
            {
                var entry = Entry(); entry.CustomData.Set("pwned-count", "1");
                Assert((bool)Invoke(plugin, "UpdateEntryRemoveBreachInformation", entry));
                Assert(!entry.CustomData.Exists("pwned-count"));
            }
            finally { DisposePlugin(plugin); }
        });
        Run("entry date stored as UTC", () =>
        {
            var plugin = new HaveIBeenPwnedPluginExt();
            try
            {
                Set(plugin, "_isModifyPwEntryDatesEnabled", true);
                var entry = Entry(); InvokeCount(plugin, entry, 1);
                Assert(entry.LastModificationTime.Kind == DateTimeKind.Utc && entry.LastAccessTime.Kind == DateTimeKind.Utc);
            }
            finally { DisposePlugin(plugin); }
        });
        Run("dates unchanged by default", () =>
        {
            var plugin = new HaveIBeenPwnedPluginExt();
            try { var entry = Entry(); var before = entry.LastModificationTime; InvokeCount(plugin, entry, 1); Assert(entry.LastModificationTime == before); }
            finally { DisposePlugin(plugin); }
        });
        Run("hashing matches UTF-8 SHA-1", () =>
        {
            var plugin = new HaveIBeenPwnedPluginExt();
            try
            {
                var entry = Entry(); entry.Strings.Set(PwDefs.PasswordField, new ProtectedString(true, "synthetic-£-密碼"));
                using (var sha1 = new SHA1Managed())
                {
                    var parts = ((string, string))Invoke(plugin, "ComputeSha1HexPartsFromEntry", entry, sha1);
                    string expected = BitConverter.ToString(sha1.ComputeHash(System.Text.Encoding.UTF8.GetBytes("synthetic-£-密碼"))).Replace("-", "");
                    Assert(parts.Item1.Length == 5 && parts.Item2.Length == 35 && parts.Item1 + parts.Item2 == expected);
                }
            }
            finally { DisposePlugin(plugin); }
        });
        Run("initialisation leaves global TLS unchanged", () =>
        {
            var before = ServicePointManager.SecurityProtocol;
            var plugin = new HaveIBeenPwnedPluginExt();
            try { plugin.Initialize(new FakeHost()); Assert(ServicePointManager.SecurityProtocol == before); }
            finally { DisposePlugin(plugin); ServicePointManager.SecurityProtocol = before; }
        });
        Run("termination after failed initialisation", () => { var plugin = new HaveIBeenPwnedPluginExt(); plugin.Initialize(null); plugin.Terminate(); plugin.Terminate(); });
        foreach (string scenario in new[] { "changed password", "switched database", "closed database", "removed entry", "replaced entry", "editor clone", "ignored during request", "disabled during request", "terminated during request" })
        {
            string captured = scenario;
            Run("discard late result: " + scenario, () => LateResult(captured).GetAwaiter().GetResult());
        }
        Run("live clean result removes tag and marks database dirty", () => LateResult("unchanged").GetAwaiter().GetResult());
        Run("duplicate checks share in-flight work", () => DuplicateChecks(false).GetAwaiter().GetResult());
        Run("changed password starts a fresh check", () => DuplicateChecks(true).GetAwaiter().GetResult());
        Run("history/editor event causes no request", () =>
        {
            var host = new FakeHost { Database = Database() }; var entry = Entry(); host.Database.RootGroup.AddEntry(entry, true);
            int requests = 0;
            var plugin = Plugin(host, new FakeHandler((r, t) => { requests++; return Task.FromResult(Response(new string('F', 35) + ":1")); }));
            try { entry.CloneDeep().Touch(true); Assert(requests == 0); }
            finally { plugin.Terminate(); host.Database.Close(); }
        });
        foreach (string scenario in new[] { "timeout", "invalid response", "HTTP error" })
        {
            string captured = scenario;
            Run("failed single check preserves breach metadata: " + scenario, () => FailedSingle(captured).GetAwaiter().GetResult());
        }
        Run("bulk progress includes ignored entries", () => BulkScan("ignored").GetAwaiter().GetResult());
        Run("empty bulk scan completes", () => BulkScan("empty").GetAwaiter().GetResult());
        Run("bulk result does not mutate changed password", () => BulkScan("changed").GetAwaiter().GetResult());
        Run("bulk stops when database switches", () => BulkScan("switched").GetAwaiter().GetResult());
        Run("bulk switch on final entry remains incomplete", () => BulkScan("switched-last").GetAwaiter().GetResult());
        Run("bulk lock preserves breach metadata", () => BulkScan("locked").GetAwaiter().GetResult());
        Run("bulk timeout preserves earlier results and ends logging", () => BulkScan("timeout").GetAwaiter().GetResult());
        Run("bulk marks original database dirty before awaiting again", () => BulkScan("dirty").GetAwaiter().GetResult());
        Run("bulk malformed response preserves metadata", () => BulkScan("invalid").GetAwaiter().GetResult());
        Run("bulk unexpected failure still ends logging", () => BulkScan("unexpected").GetAwaiter().GetResult());
        Run("termination cancels pending HTTP request", () => FailedSingle("shutdown").GetAwaiter().GetResult());
        Run("bad prefix rejected before sending", () =>
        {
            int requests = 0;
            using (var hibp = NewClient(new FakeHandler((r, t) => { requests++; return Task.FromResult(Response(Suffix + ":1")); })))
            {
                Throws<ArgumentException>(() => hibp.CheckRangeAsync("21BD1/extra", Suffix).GetAwaiter().GetResult());
                Assert(requests == 0);
            }
        });
        RunWorkerEventTests();
        int dashboarderOption = Array.IndexOf(args, "--dashboarder");
        if (dashboarderOption >= 0)
        {
            if (dashboarderOption + 1 >= args.Length) throw new ArgumentException("Supply the Dashboarder test assembly path.");
            RunDashboarderTests(args[dashboarderOption + 1]);
        }
        int fluentOption = Array.IndexOf(args, "--fluent");
        if (fluentOption >= 0)
        {
            if (fluentOption + 1 >= args.Length) throw new ArgumentException("Supply the Fluent Theme DLL path.");
            RunFluentTests(args[fluentOption + 1]);
        }
        if (Array.IndexOf(args, "--live") >= 0)
            Run("live HIBP query for documented synthetic fixture", () =>
            {
                using (var hibp = new HIBP()) { var result = Check(hibp).GetAwaiter().GetResult(); Assert(result.Item1 && result.Item2 > 0); }
            });
        Console.WriteLine($"Passed: {_passed}; failed: {_failed}");
        Environment.ExitCode = _failed == 0 ? 0 : 1;
    }

    private static async Task FailedSingle(string scenario)
    {
        var host = new FakeHost { Database = Database() }; var entry = Entry(); host.Database.RootGroup.AddEntry(entry, true);
        entry.AddTag("pwned"); entry.CustomData.Set("pwned-count", "4");
        bool cancelled = false;
        var client = new HttpClient(new FakeHandler(async (r, token) =>
        {
            if (scenario == "invalid response") return Response("not-a-range");
            if (scenario == "HTTP error") return new HttpResponseMessage(HttpStatusCode.ServiceUnavailable);
            try { await Task.Delay(Timeout.Infinite, token); }
            catch (OperationCanceledException) { cancelled = true; throw; }
            return Response("");
        }));
        var plugin = new HaveIBeenPwnedPluginExt();
        ((HIBP)typeof(HaveIBeenPwnedPluginExt).GetField("_hibp", Private).GetValue(plugin)).Dispose();
        Set(plugin, "_hibp", NewClient(client)); plugin.Initialize(host);
        Set(plugin, "_hasReportedHibpError", true); // Suppress modal notifications in this headless harness.
        client.Timeout = TimeSpan.FromMilliseconds(50);
        try
        {
            Task task = CheckEntry(plugin, entry, null, true);
            if (scenario == "shutdown") plugin.Terminate();
            await task.ConfigureAwait(false);
            Assert(entry.HasTag("pwned") && entry.CustomData.Get("pwned-count") == "4" && !host.Database.Modified);
            if (scenario == "timeout" || scenario == "shutdown") Assert(cancelled);
        }
        finally { DisposePlugin(plugin); host.Database.Close(); }
    }

    private static async Task BulkScan(string scenario)
    {
        var host = new FakeHost { Database = Database() }; var original = host.Database;
        var first = Entry(); first.AddTag("pwned"); first.CustomData.Set("pwned-count", "4");
        var second = Entry(); second.AddTag("pwned"); second.CustomData.Set("pwned-count", "4");
        if (scenario != "empty") { original.RootGroup.AddEntry(first, true); if (scenario != "switched-last") original.RootGroup.AddEntry(second, true); }
        if (scenario == "ignored") { first.AddTag("pwned-ignore"); second.Strings.Set(PwDefs.PasswordField, ProtectedString.Empty); }
        var pending = new TaskCompletionSource<HttpResponseMessage>(); int requests = 0;
        var secondStarted = new TaskCompletionSource<bool>();
        var logger = new FakeLogger();
        var plugin = Plugin(host, new FakeHandler((r, token) =>
        {
            requests++;
            if (requests == 2) secondStarted.TrySetResult(true);
            if (scenario == "unexpected") throw new InvalidOperationException("synthetic failure");
            if (requests == 1 && (scenario == "dirty" || scenario == "timeout")) return Task.FromResult(Response(new string('F', 35) + ":1"));
            return pending.Task;
        }));
        Set(plugin, "_hasReportedHibpError", true);
        try
        {
            var task = (Task<string[]>)Invoke(plugin, "CheckAllPasswordsAsync", original, logger);
            if (scenario == "changed") { first.Strings.Set(PwDefs.PasswordField, new ProtectedString(true, "changed-synthetic")); second.AddTag("pwned-ignore"); }
            if (scenario == "switched" || scenario == "switched-last") host.Database = Database();
            if (scenario == "locked") original.Close();
            if (scenario == "dirty")
            {
                Assert(await Task.WhenAny(secondStarted.Task, Task.Delay(5000)) == secondStarted.Task);
                Assert(requests == 2 && original.Modified && !first.HasTag("pwned"));
                second.AddTag("pwned-ignore");
            }
            if (scenario == "timeout") pending.SetException(new TaskCanceledException("synthetic timeout"));
            else pending.SetResult(Response(scenario == "invalid" ? "invalid" : new string('F', 35) + ":1"));
            if (scenario == "unexpected")
            {
                try { await task; throw new Exception("Expected failure"); } catch (InvalidOperationException) { }
            }
            else
            {
                string[] summary = await task;
                if (scenario == "ignored") Assert(requests == 0 && logger.Progress == 100 && Array.IndexOf(summary, "Checked entries: 0") >= 0);
                if (scenario == "empty") Assert(requests == 0 && Array.IndexOf(summary, "Checked entries: 0") >= 0);
                if (scenario == "changed") Assert(first.HasTag("pwned") && !original.Modified);
                if (scenario == "switched" || scenario == "switched-last") Assert(requests == 1 && first.HasTag("pwned") && !host.Database.Modified && summary[0].Contains("incomplete"));
                if (scenario == "timeout") Assert(!first.HasTag("pwned") && second.HasTag("pwned") && original.Modified && Array.IndexOf(summary, "Checked entries: 1") >= 0 && summary[0].Contains("incomplete"));
                if (scenario == "locked") Assert(first.HasTag("pwned") && summary[0].Contains("incomplete"));
                if (scenario == "invalid") Assert(first.HasTag("pwned") && !original.Modified && summary[0].Contains("incomplete"));
            }
            Assert(logger.Started && logger.Ended && !(bool)typeof(HaveIBeenPwnedPluginExt).GetField("_isBulkCheckRunning", Private).GetValue(plugin));
        }
        finally { DisposePlugin(plugin); if (host.Database != original) host.Database.Close(); original.Close(); }
    }

    private static async Task LateResult(string scenario)
    {
        var response = new TaskCompletionSource<HttpResponseMessage>();
        var host = new FakeHost { Database = Database() }; var original = host.Database;
        var entry = Entry(); entry.AddTag("pwned"); entry.CustomData.Set("pwned-count", "4"); original.RootGroup.AddEntry(entry, true);
        var plugin = Plugin(host, new FakeHandler((r, t) => response.Task));
        bool callback = false;
        try
        {
            PwEntry target = scenario == "editor clone" ? entry.CloneDeep() : entry;
            var task = CheckEntry(plugin, target, () => callback = true, true);
            switch (scenario)
            {
                case "changed password": entry.Strings.Set(PwDefs.PasswordField, new ProtectedString(true, "different-synthetic")); break;
                case "switched database": host.Database = Database(); break;
                case "closed database": original.Close(); break;
                case "removed entry": original.RootGroup.Entries.Remove(entry); break;
                case "replaced entry": var copy = entry.CloneDeep(); original.RootGroup.Entries.Remove(entry); original.RootGroup.AddEntry(copy, true); break;
                case "ignored during request": entry.AddTag("pwned-ignore"); break;
                case "disabled during request": Set(plugin, "_checkPasswordOnEntryTouched", false); break;
                case "terminated during request": plugin.Terminate(); break;
            }
            response.SetResult(Response(new string('F', 35) + ":1"));
            await task.ConfigureAwait(false);
            if (scenario == "unchanged") Assert(!entry.HasTag("pwned") && original.Modified && callback);
            else Assert(entry.HasTag("pwned") && entry.CustomData.Get("pwned-count") == "4" && !callback);
        }
        finally { DisposePlugin(plugin); if (host.Database != original) host.Database.Close(); original.Close(); }
    }

    private static async Task DuplicateChecks(bool changedPassword)
    {
        var responses = new List<TaskCompletionSource<HttpResponseMessage>>();
        var host = new FakeHost { Database = Database() }; var entry = Entry(); host.Database.RootGroup.AddEntry(entry, true);
        var plugin = Plugin(host, new FakeHandler((r, t) => { var result = new TaskCompletionSource<HttpResponseMessage>(); responses.Add(result); return result.Task; }));
        try
        {
            Task first = CheckEntry(plugin, entry, null, false);
            if (changedPassword) entry.Strings.Set(PwDefs.PasswordField, new ProtectedString(true, "changed-synthetic"));
            Task second = CheckEntry(plugin, entry, null, false);
            int requests = responses.Count;
            foreach (var response in responses) response.SetResult(Response(new string('F', 35) + ":1"));
            await Task.WhenAll(first, second);
            Assert(requests == (changedPassword ? 2 : 1));
        }
        finally { DisposePlugin(plugin); host.Database.Close(); }
    }

    private static HaveIBeenPwnedPluginExt Plugin(FakeHost host, FakeHandler handler)
    {
        var plugin = new HaveIBeenPwnedPluginExt();
        ((HIBP)typeof(HaveIBeenPwnedPluginExt).GetField("_hibp", Private).GetValue(plugin)).Dispose();
        Set(plugin, "_hibp", NewClient(handler)); plugin.Initialize(host); return plugin;
    }
    private static Task CheckEntry(HaveIBeenPwnedPluginExt plugin, PwEntry entry, Action callback, bool automatic)
    {
        var method = typeof(HaveIBeenPwnedPluginExt).GetMethod("CheckHaveIBeenPwnedForEntry", Private);
        return (Task)method.Invoke(plugin, method.GetParameters().Length == 3 ? new object[] { entry, callback, automatic } : new object[] { entry, callback });
    }
    private static object InvokeCount(HaveIBeenPwnedPluginExt plugin, PwEntry entry, long count)
    {
        var method = typeof(HaveIBeenPwnedPluginExt).GetMethod("UpdateEntryWithBreachInformation", Private);
        object value = method.GetParameters()[1].ParameterType == typeof(int) ? (object)(int)count : count;
        return method.Invoke(plugin, new[] { (object)entry, value });
    }
    private static void DisposePlugin(HaveIBeenPwnedPluginExt plugin)
    {
        // Also lets this harness demonstrate the original failed-initialisation bug without hiding test results.
        if (typeof(HaveIBeenPwnedPluginExt).GetField("_pluginHost", Private).GetValue(plugin) == null) Set(plugin, "_pluginHost", new FakeHost());
        plugin.Terminate();
    }
    private static object Invoke(object instance, string method, params object[] args) => instance.GetType().GetMethod(method, Private).Invoke(instance, args);
    private static void Set(object instance, string field, object value) => instance.GetType().GetField(field, Private).SetValue(instance, value);
    private static PwEntry Entry() { var entry = new PwEntry(true, true); entry.Strings.Set(PwDefs.PasswordField, new ProtectedString(true, "synthetic-regression-fixture")); return entry; }
    private static PwDatabase Database() { var db = new PwDatabase(); db.New(new IOConnectionInfo { Path = "synthetic-regression.kdbx" }, new CompositeKey()); db.Modified = false; return db; }
    private static HttpResponseMessage Response(string body) => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(body) };
    private static HIBP NewClient(FakeHandler handler) => NewClient(new HttpClient(handler));
    private static HIBP NewClient(HttpClient client)
    {
        var constructor = typeof(HIBP).GetConstructor(Private, null, new[] { typeof(HttpClient) }, null);
        if (constructor != null) return (HIBP)constructor.Invoke(new object[] { client });
        typeof(HIBP).GetField("s_httpClient", BindingFlags.Static | BindingFlags.NonPublic).SetValue(null, client);
        return new HIBP();
    }
    private static async Task<(bool, long)> Check(HIBP hibp)
    {
        var method = typeof(HIBP).GetMethod("CheckRangeAsync", new[] { typeof(string), typeof(string), typeof(CancellationToken) }) ??
                     typeof(HIBP).GetMethod("CheckRangeAsync", new[] { typeof(string), typeof(string) });
        Task task = (Task)method.Invoke(hibp, method.GetParameters().Length == 3 ? new object[] { "21BD1", Suffix, CancellationToken.None } : new object[] { "21BD1", Suffix });
        await task.ConfigureAwait(false);
        object result = task.GetType().GetProperty("Result").GetValue(task);
        return ((bool)result.GetType().GetField("Item1").GetValue(result), Convert.ToInt64(result.GetType().GetField("Item2").GetValue(result)));
    }
    private static (bool, long) Query(string body) { using (var hibp = NewClient(new FakeHandler((r, t) => Task.FromResult(Response(body))))) return Check(hibp).GetAwaiter().GetResult(); }
    private static void CheckResponse(string body, bool breached, long count) { var result = Query(body); Assert(result.Item1 == breached && result.Item2 == count); }
    private static void Assert(bool condition) { if (!condition) throw new Exception("Assertion failed."); }
    private static void Throws<T>(Action action) where T : Exception { try { action(); } catch (T) { return; } throw new Exception("Expected " + typeof(T).Name); }
    private static void Run(string name, Action action)
    {
        try { action(); _passed++; Console.WriteLine("PASS " + name); }
        catch (Exception error) { _failed++; Console.WriteLine("FAIL " + name + ": " + error.GetBaseException().GetType().Name + " " + error.GetBaseException().Message); }
    }
    private sealed class FakeHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> _send;
        internal FakeHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) => _send = send;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) => _send(request, cancellationToken);
    }
    private sealed class FakeLogger : KeePassLib.Interfaces.IStatusLogger
    {
        internal bool Started, Ended;
        internal uint Progress;
        public void StartLogging(string operation, bool writeToLog) => Started = true;
        public void EndLogging() => Ended = true;
        public bool SetProgress(uint progress) { Progress = progress; return true; }
        public bool SetText(string text, KeePassLib.Interfaces.LogStatusType type) => true;
        public bool ContinueWork() => true;
    }
    private sealed class FakeHost : IPluginHost
    {
        public MainForm MainWindow => null;
        private PwDatabase _database;
        internal Action OnDatabaseRead;
        public PwDatabase Database { get { OnDatabaseRead?.Invoke(); return _database; } set { _database = value; } }
        public AceCustomConfig CustomConfig { get; } = new AceCustomConfig();
        public CommandLineArgs CommandLineArgs => null;
        public CipherPool CipherPool => null;
        public KeyProviderPool KeyProviderPool => null;
        public KeyValidatorPool KeyValidatorPool => null;
        public FileFormatPool FileFormatPool => null;
        public TempFilesPool TempFilesPool => null;
        public EcasPool EcasPool => null;
        public EcasTriggerSystem TriggerSystem => null;
        public CustomPwGeneratorPool PwGeneratorPool => null;
        public ColumnProviderPool ColumnProviderPool => null;
        public ResourceManager Resources => null;
    }
}
