using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Drawing;
using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Runtime.Serialization;
using System.Threading;
using System.Threading.Tasks;
using HaveIBeenPwnedPlugin;
using KeePassLib;

internal static partial class Program
{
    private static void RunWorkerEventTests()
    {
        foreach (string scenario in new[] { "icon touch", "duplicate touches", "ignored entry", "shutdown before dispatch" })
        {
            string captured = scenario;
            Run("worker compatibility: " + scenario, () => WorkerEvent(captured));
        }
    }

    private static void WorkerEvent(string scenario)
    {
        var previousContext = SynchronizationContext.Current;
        var context = new PumpContext();
        SynchronizationContext.SetSynchronizationContext(context);
        int uiThread = Thread.CurrentThread.ManagedThreadId;
        var database = Database(); var entry = Entry(); database.RootGroup.AddEntry(entry, true);
        entry.AddTag("pwned"); entry.CustomData.Set("pwned-count", "4");
        if (scenario == "ignored entry") entry.AddTag("pwned-ignore");
        var host = new FakeHost { Database = database };
        var response = new TaskCompletionSource<HttpResponseMessage>();
        int requests = 0; bool wrongThread = false;
        var plugin = Plugin(host, new FakeHandler((r, t) =>
        {
            requests++;
            wrongThread |= Thread.CurrentThread.ManagedThreadId != uiThread;
            return response.Task;
        }));
        host.OnDatabaseRead = () => wrongThread |= Thread.CurrentThread.ManagedThreadId != uiThread;
        try
        {
            Task.Run(() =>
            {
                entry.CustomIconUuid = new PwUuid(true);
                if (scenario == "duplicate touches")
                    Parallel.For(0, 16, i => entry.Touch(true));
                else entry.Touch(true);
            }).GetAwaiter().GetResult();
            bool deferred = requests == 0;
            if (scenario == "shutdown before dispatch") plugin.Terminate();
            context.Drain();
            if (scenario == "ignored entry" || scenario == "shutdown before dispatch")
            {
                Assert(requests == 0 && entry.HasTag("pwned") && !wrongThread);
            }
            else
            {
                context.Until(() => requests > 0);
                PwUuid icon = entry.CustomIconUuid;
                Task.Run(() => response.TrySetResult(Response(new string('F', 35) + ":1"))).GetAwaiter().GetResult();
                context.Until(() => !entry.HasTag("pwned"));
                Assert(deferred && requests == 1 && !wrongThread && entry.CustomIconUuid.Equals(icon));
                Assert(database.Modified && entry.CustomData.Get("pwned-count") == null);
            }
        }
        finally
        {
            plugin.Terminate();
            response.TrySetCanceled();
            context.Drain();
            database.Close();
            SynchronizationContext.SetSynchronizationContext(previousContext);
        }
    }

    private static void RunDashboarderTests(string assemblyPath)
    {
        var assembly = Assembly.LoadFrom(System.IO.Path.GetFullPath(assemblyPath));
        Assert(assembly.GetName().Name == "CustomIconDashboarderPlugin");
        foreach (bool sharedIcon in new[] { false, true })
        {
            bool captured = sharedIcon;
            Run("Dashboarder " + assembly.GetName().Version + " actual " + (sharedIcon ? "shared-icon replacement" : "entry-icon replacement"),
                () => DashboarderIconChange(assembly, captured));
        }
        Run("Dashboarder TLS configuration is not overwritten by HIBP", () =>
        {
            var before = ServicePointManager.SecurityProtocol;
            var plugin = new HaveIBeenPwnedPluginExt();
            try
            {
                assembly.GetType("CustomIconDashboarderPlugin.BestIconFinder", true).GetMethod("InitClass").Invoke(null, null);
                var dashboarderPolicy = ServicePointManager.SecurityProtocol;
                plugin.Initialize(new FakeHost());
                Assert(ServicePointManager.SecurityProtocol == dashboarderPolicy);
            }
            finally { plugin.Terminate(); ServicePointManager.SecurityProtocol = before; }
        });
    }

    private static void DashboarderIconChange(Assembly assembly, bool sharedIcon)
    {
        var previousContext = SynchronizationContext.Current;
        var context = new PumpContext();
        SynchronizationContext.SetSynchronizationContext(context);
        int uiThread = Thread.CurrentThread.ManagedThreadId;
        var database = Database();
        var first = Entry(); var second = Entry();
        database.RootGroup.AddEntry(first, true);
        if (sharedIcon) database.RootGroup.AddEntry(second, true);
        var entries = sharedIcon ? new[] { first, second } : new[] { first };
        foreach (var entry in entries) { entry.AddTag("pwned"); entry.CustomData.Set("pwned-count", "4"); }
        var password = first.Strings.GetSafe(PwDefs.PasswordField);
        var host = new FakeHost { Database = database };
        var responses = new List<TaskCompletionSource<HttpResponseMessage>>();
        bool wrongThread = false;
        var plugin = Plugin(host, new FakeHandler((r, t) =>
        {
            wrongThread |= Thread.CurrentThread.ManagedThreadId != uiThread;
            var response = new TaskCompletionSource<HttpResponseMessage>();
            responses.Add(response);
            return response.Task;
        }));
        host.OnDatabaseRead = () => wrongThread |= Thread.CurrentThread.ManagedThreadId != uiThread;
        // Exercise the released source's mutation methods without constructing/showing
        // its forms, running menu handlers or performing favicon network requests.
        Type dashboardType = assembly.GetType("CustomIconDashboarderPlugin.DashboarderForm", true);
        object dashboard = FormatterServices.GetUninitializedObject(dashboardType);
        GC.SuppressFinalize(dashboard);
        dashboardType.GetField("lckKdbCustomIcons", Private).SetValue(dashboard, new object());
        bool dashboardDispatches = dashboardType.GetField("m_uiThreadId", Private) != null;
        if (dashboardDispatches)
        {
            dashboardType.GetField("m_uiThreadId", Private).SetValue(dashboard, uiThread);
            dashboardType.GetField("m_uiContext", Private).SetValue(dashboard, context);
            dashboardType.GetField("m_database", Private).SetValue(dashboard, database);
            dashboardType.GetField("m_databaseRoot", Private).SetValue(dashboard, database.RootGroup);
            dashboardType.GetField("m_PluginHost", Private).SetValue(dashboard, host);
        }
        try
        {
            using (var image = new Bitmap(8, 8))
            {
                using (var graphics = Graphics.FromImage(image)) graphics.Clear(Color.CornflowerBlue);
                PwCustomIcon oldIcon = null;
                if (sharedIcon)
                {
                    using (var oldImage = new Bitmap(4, 4))
                    using (var stream = new System.IO.MemoryStream())
                    {
                        oldImage.Save(stream, System.Drawing.Imaging.ImageFormat.Png);
                        oldIcon = new PwCustomIcon(new PwUuid(true), stream.ToArray());
                    }
                    database.CustomIcons.Add(oldIcon);
                    first.CustomIconUuid = second.CustomIconUuid = database.RootGroup.CustomIconUuid = oldIcon.Uuid;
                    var stats = assembly.CreateInstance("CustomIconDashboarderPlugin.IconStatsHandler");
                    stats.GetType().GetMethod("Initialize").Invoke(stats, new object[] { database });
                    dashboardType.GetField("m_iconCounter", Private).SetValue(dashboard, stats);
                }
                PwCustomIcon result = null;
                PwCustomIcon previousIcon = oldIcon;
                Task worker = Task.Run(() =>
                {
                    result = (PwCustomIcon)dashboardType.GetMethod(sharedIcon ? "UpdateCustomIconFromImage" : "UpdateEntryFromImage", Private)
                        .Invoke(dashboard, new object[] { sharedIcon ? (object)previousIcon : first, image, database });
                });
                context.Until(() => worker.IsCompleted);
                worker.GetAwaiter().GetResult();
                Assert(result != null);
                bool deferred = responses.Count == 0;
                Assert(first.HasTag("pwned") && first.CustomData.Get("pwned-count") == "4");
                context.Until(() => responses.Count == entries.Length);
                foreach (var response in responses) response.SetResult(Response(new string('F', 35) + ":1"));
                context.Until(() => { foreach (var entry in entries) if (entry.HasTag("pwned")) return false; return true; });
                foreach (var entry in entries) Assert(entry.CustomIconUuid.Equals(result.Uuid) && entry.CustomData.Get("pwned-count") == null);
                Assert((dashboardDispatches || deferred) && !wrongThread && ReferenceEquals(password, first.Strings.GetSafe(PwDefs.PasswordField)));
                Assert(database.Modified && database.UINeedsIconUpdate);
                if (sharedIcon) Assert(database.RootGroup.CustomIconUuid.Equals(result.Uuid));
                InvokeCount(plugin, first, 42);
                Assert(first.CustomIconUuid.Equals(result.Uuid) && first.HasTag("pwned") && first.CustomData.Get("pwned-count") == "42");
            }
        }
        finally
        {
            plugin.Terminate();
            foreach (var response in responses) response.TrySetCanceled();
            context.Drain();
            database.Close();
            SynchronizationContext.SetSynchronizationContext(previousContext);
        }
    }

    private sealed class PumpContext : SynchronizationContext
    {
        private readonly ConcurrentQueue<Action> _queue = new ConcurrentQueue<Action>();
        public override void Post(SendOrPostCallback callback, object state) => _queue.Enqueue(() => callback(state));
        public override void Send(SendOrPostCallback callback, object state)
        {
            using (var done = new ManualResetEventSlim())
            {
                Exception error = null;
                _queue.Enqueue(() => { try { callback(state); } catch (Exception caught) { error = caught; } finally { done.Set(); } });
                if (!done.Wait(TimeSpan.FromSeconds(5))) throw new TimeoutException("Compatibility UI dispatch timed out.");
                if (error != null) System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(error).Throw();
            }
        }
        internal void Drain() { while (_queue.TryDequeue(out Action callback)) callback(); }
        internal void Until(Func<bool> complete)
        {
            DateTime deadline = DateTime.UtcNow.AddSeconds(5);
            while (!complete())
            {
                Drain();
                if (DateTime.UtcNow >= deadline) throw new TimeoutException("Compatibility check did not complete.");
                Thread.Sleep(1);
            }
            Drain();
        }
    }
}
