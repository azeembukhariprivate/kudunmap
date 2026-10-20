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
            if (cmd.SelfTest)
            {
                ShutdownMode = ShutdownMode.OnExplicitShutdown;
                Shutdown(SelfTest.Run());
                return;
            }

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
