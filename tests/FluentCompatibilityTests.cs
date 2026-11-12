using System;
using System.Drawing;
using System.Reflection;
using System.Windows.Forms;
using HaveIBeenPwnedPlugin;
using KeePassLib;

internal static partial class Program
{
    private static void RunFluentTests(string assemblyPath)
    {
        var assembly = Assembly.LoadFrom(System.IO.Path.GetFullPath(assemblyPath));
        Assert(assembly.GetName().Name == "FluentTheme" && assembly.GetName().Version == new Version(1, 5, 2026, 1111));
        foreach (bool dark in new[] { false, true })
        {
            bool captured = dark;
            Run("Fluent Theme 1.5.2026.1111 tag repaint, " + (dark ? "dark" : "light"), () => FluentTags(assembly, captured));
        }
    }

    private static void FluentTags(Assembly assembly, bool dark)
    {
        var database = Database(); var entry = Entry(); database.RootGroup.AddEntry(entry, true);
        var host = new FakeHost { Database = database };
        var plugin = new HaveIBeenPwnedPluginExt();
        Type panelType = assembly.GetType("FluentTheme.DetailsPanel", true);
        Type paletteType = assembly.GetType("FluentTheme.Palette", true);
        using (var list = new ListView())
        using (var panel = (Control)Activator.CreateInstance(panelType, new object[] { host, list, null }))
        {
            try
            {
                panel.Size = new Size(1000, 600);
                object palette = paletteType.GetMethod("Create").Invoke(null, new object[] { dark, Color.CornflowerBlue });
                panelType.GetMethod("SetPalette").Invoke(panel, new object[] { palette, 1f });
                panelType.GetField("m_entry", Private).SetValue(panel, entry);
                DateTime before = entry.LastModificationTime;
                DrawTheme(panel);
                int initialHits = TagHitCount(panelType, panel);
                InvokeCount(plugin, entry, 42);
                DrawTheme(panel);
                Assert(TagHitCount(panelType, panel) == initialHits + 1 && entry.LastModificationTime == before);
                Assert(entry.CustomData.Get("pwned-count") == "42");
                Invoke(plugin, "UpdateEntryRemoveBreachInformation", entry);
                DrawTheme(panel);
                Assert(TagHitCount(panelType, panel) == initialHits && entry.LastModificationTime == before);
            }
            finally { DisposePlugin(plugin); database.Close(); }
        }
    }

    private static void DrawTheme(Control panel)
    {
        // Off-screen synthetic rendering only; no application window is shown.
        using (var image = new Bitmap(panel.Width, panel.Height)) panel.DrawToBitmap(image, panel.ClientRectangle);
    }

    private static int TagHitCount(Type panelType, object panel)
    {
        object hits = panelType.GetField("m_hits", Private).GetValue(panel);
        int count = 0;
        foreach (object hit in (System.Collections.IEnumerable)hits)
        {
            // The header tag creates a distinct navigation action. Count the tooltip
            // containing the synthetic pwned tag, without relying on translated text.
            foreach (var field in hit.GetType().GetFields(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic))
                if (field.FieldType == typeof(string) && (field.GetValue(hit) as string)?.Contains("pwned") == true) count++;
        }
        return count;
    }
}
