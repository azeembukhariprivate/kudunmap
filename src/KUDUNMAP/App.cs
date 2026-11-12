using System;
using System.Windows;
using System.Windows.Threading;
using Kudunmap.Core;
using Kudunmap.Views;

namespace Kudunmap
{
    public static class Program
    {
        [STAThread]
        public static int Main() => new App().Run();
    }

    public sealed class App : Application
    {
        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);
            ShutdownMode = ShutdownMode.OnMainWindowClose;
            DispatcherUnhandledException += OnUnhandledException;
            Exporter.AppVersion = AppInfo.VersionText;

            var cmd = CommandLine.Parse(e.Args);
            if (cmd.DataFolder != null) AppPaths.Root = cmd.DataFolder;
            if (cmd.RemoveSchedules)
            {
                try { ScheduledScans.RemoveAll(); }
                catch { /* uninstalling goes on */ }
                Shutdown(0);
                return;
            }
            if (cmd.Scheduled != null)
            {
                ShutdownMode = ShutdownMode.OnExplicitShutdown;
                ScheduledRun.Start(this, cmd.Scheduled);
                return;
            }
            if (cmd.SelfTest)
            {
                ShutdownMode = ShutdownMode.OnExplicitShutdown;
                Shutdown(SelfTest.Run());
                return;
            }

            SafetyNet.Install(); // says so if an error behind the window closes the app

            LangUi.Start(); // the app in the chosen language
            ThemeManager.Init(Settings.Theme);
            ThemeManager.WatchSystem();

            var main = new MainWindow(cmd);
            MainWindow = main;
            main.Show();
        }

        private void OnUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
        {
            if (SelfTest.Running)
            {
                SelfTest.Errors.Add(e.Exception.ToString());
                e.Handled = true;
                return;
            }
            Dialogs.Error(MainWindow?.IsVisible == true ? MainWindow : null, "Something went wrong:\n\n" + e.Exception.Message);
            e.Handled = true;
        }
    }
}
