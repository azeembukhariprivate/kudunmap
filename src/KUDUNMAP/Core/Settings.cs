// KUDUNMAP's settings, kept in the registry for the current user.
using System;
using Microsoft.Win32;

namespace Kudunmap.Core
{
    /// <summary>How the app looks: like Windows, always light, or always dark.</summary>
    public enum ThemeMode { System, Light, Dark }

    /// <summary>Settings are stored under HKEY_CURRENT_USER, so no administrator rights are needed.</summary>
    public static class Settings
    {
        /// <summary>Where the settings are kept, under HKEY_CURRENT_USER.</summary>
        private const string KeyPath = @"Software\KUDUNMAP";

        /// <summary>A setting as text, or fallback when it isn't there or can't be read.</summary>
        private static string Get(string name, string fallback)
        {
            try
            {
                using (var key = Registry.CurrentUser.OpenSubKey(KeyPath))
                {
                    return key?.GetValue(name) as string ?? fallback;
                }
            }
            catch
            {
                return fallback;
            }
        }

        /// <summary>Keeps a setting (quietly does nothing when the registry can't be written).</summary>
        private static void Set(string name, string value)
        {
            try
            {
                using (var key = Registry.CurrentUser.CreateSubKey(KeyPath))
                {
                    key?.SetValue(name, value ?? string.Empty);
                }
            }
            catch
            {
                // Settings are best-effort.
            }
        }

        /// <summary>A yes/no setting (kept as "1" or "0").</summary>
        private static bool GetBool(string name, bool fallback) => Get(name, fallback ? "1" : "0") == "1";
        /// <summary>Keeps a yes/no setting.</summary>
        private static void SetBool(string name, bool value) => Set(name, value ? "1" : "0");

        public static ThemeMode Theme
        {
            get => Enum.TryParse(Get("Theme", "System"), out ThemeMode mode) ? mode : ThemeMode.System;
            set => Set("Theme", value.ToString());
        }

        public static bool CheckForUpdates
        {
            get => GetBool("CheckForUpdates", true);
            set => SetBool("CheckForUpdates", value);
        }

        public static string SkippedVersion
        {
            get => Get("SkippedVersion", string.Empty);
            set => Set("SkippedVersion", value);
        }

        /// <summary>nmap.exe chosen by hand. Empty means "find it automatically".</summary>
        public static string NmapPath
        {
            get => Get("NmapPath", string.Empty);
            set => Set("NmapPath", value);
        }

        /// <summary>The one-time "only scan what you own" notice was confirmed.</summary>
        public static bool NoticeAccepted
        {
            get => GetBool("NoticeAccepted", false);
            set => SetBool("NoticeAccepted", value);
        }

        public static bool NotifyWhenDone
        {
            get => GetBool("NotifyWhenDone", true);
            set => SetBool("NotifyWhenDone", value);
        }

        public static bool ShowAdvancedScripts
        {
            get => GetBool("ShowAdvancedScripts", false);
            set => SetBool("ShowAdvancedScripts", value);
        }

        public static string LastPreset
        {
            get => Get("LastPreset", "services");
            set => Set("LastPreset", value);
        }

        public static string LastTarget
        {
            get => Get("LastTarget", string.Empty);
            set => Set("LastTarget", value);
        }
    }
}
