// Where KUDUNMAP starts: the command line decides whether it runs a scheduled scan, the self-test, the install check,
// removes or limits the schedules, or opens the main window.
using System;
using System.Windows;
using System.Windows.Threading;
using Kudunmap.Core;
using Kudunmap.Views;

namespace Kudunmap
{
    public static class Program
    {
        /// <summary>Starts the app.</summary>
        [STAThread]
        public static int Main() => new App().Run();
    }

    public sealed class App : Application
    {
        /// <summary>
        /// Reads the command line, sets up the theme and language, and does or opens what was asked for.
        /// </summary>
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
            if (cmd.LimitSchedules)
            {
                try { SchedulesWindow.LimitRights(null); }
                catch { /* done again when KUDUNMAP is opened */ }
                Shutdown(0);
                return;
            }
            if (cmd.Scheduled != null)
            {
                ShutdownMode = ShutdownMode.OnExplicitShutdown;
                ScheduledRun.Start(this, cmd.Scheduled);
                return;
            }
            if (cmd.InstallCheck)
            {
                ShutdownMode = ShutdownMode.OnExplicitShutdown;
                Shutdown(InstallCheck.Run());
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

        /// <summary>
        /// Shows an error that wasn't expected instead of closing the app (the self-test keeps it as a failure).
        /// </summary>
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
