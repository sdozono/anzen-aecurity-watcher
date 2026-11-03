using System.Windows;
using System.Windows.Media;
using Microsoft.Win32;

namespace AnzenSecurityWatcher.Services;

public enum AppThemeMode
{
    System = 0, // システム設定に追従 (デフォルト)
    Light = 1,  // ライトモード
    Dark = 2    // ダークモード
}

public static class ThemeManager
{
    public static AppThemeMode CurrentMode { get; private set; } = AppThemeMode.System;
    public static bool IsCurrentlyDark { get; private set; } = true;

    public static event Action<bool>? OnThemeChanged;

    static ThemeManager()
    {
        SystemEvents.UserPreferenceChanged += (_, e) =>
        {
            if (CurrentMode == AppThemeMode.System &&
                (e.Category == UserPreferenceCategory.General || e.Category == UserPreferenceCategory.VisualStyle))
            {
                System.Windows.Application.Current?.Dispatcher.BeginInvoke(() => ApplyTheme(AppThemeMode.System));
            }
        };
    }

    public static bool DetectWindowsDarkMode()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
            if (key?.GetValue("AppsUseLightTheme") is int val)
            {
                return val == 0; // 0 = Dark, 1 = Light
            }
        }
        catch
        {
            // Ignore registry access error
        }
        return false; // Windows 11 default is Light if key missing
    }

    public static void ApplyTheme(AppThemeMode mode)
    {
        CurrentMode = mode;
        bool isDark = mode switch
        {
            AppThemeMode.Dark => true,
            AppThemeMode.Light => false,
            _ => DetectWindowsDarkMode()
        };

        IsCurrentlyDark = isDark;
        var res = System.Windows.Application.Current?.Resources;
        if (res == null) return;

        if (isDark)
        {
            SetBrush(res, "WindowBgBrush", "#0F141C");
            SetBrush(res, "HeaderBgBrush", "#161D29");
            SetBrush(res, "PanelBgBrush", "#141B25");
            SetBrush(res, "SubPanelBgBrush", "#18202D");
            SetBrush(res, "CardBgBrush", "#1D2636");
            SetBrush(res, "InputBgBrush", "#0B0F15");
            SetBrush(res, "BorderBrushPrimary", "#283245");
            SetBrush(res, "BorderBrushSecondary", "#364156");
            SetBrush(res, "TextPrimaryBrush", "#E6EDF3");
            SetBrush(res, "TextStrongBrush", "#FFFFFF");
            SetBrush(res, "TextMutedBrush", "#8B949E");
            SetBrush(res, "TextAccentBrush", "#58A6FF");
            SetBrush(res, "TextSubHeaderBrush", "#9ECBFF");
            SetBrush(res, "ButtonBgBrush", "#212836");
            SetBrush(res, "ButtonHoverBgBrush", "#2E384D");
            SetBrush(res, "TabInactiveBgBrush", "#161D29");
            SetBrush(res, "TabHoverBgBrush", "#212B3D");
            SetBrush(res, "GridRowBgBrush", "#141B25");
            SetBrush(res, "GridAltRowBgBrush", "#18202C");
            SetBrush(res, "GridHeaderBgBrush", "#1E2736");
            SetBrush(res, "GridLineBrush", "#222C3C");
            SetBrush(res, "GridSelectedBgBrush", "#264F78");
            SetBrush(res, "GridSelectedFgBrush", "#FFFFFF");
        }
        else
        {
            SetBrush(res, "WindowBgBrush", "#F2F5F9");
            SetBrush(res, "HeaderBgBrush", "#FFFFFF");
            SetBrush(res, "PanelBgBrush", "#FFFFFF");
            SetBrush(res, "SubPanelBgBrush", "#F7F9FC");
            SetBrush(res, "CardBgBrush", "#EDF2F8");
            SetBrush(res, "InputBgBrush", "#FFFFFF");
            SetBrush(res, "BorderBrushPrimary", "#D0D7DE");
            SetBrush(res, "BorderBrushSecondary", "#B6C0CC");
            SetBrush(res, "TextPrimaryBrush", "#1F2328");
            SetBrush(res, "TextStrongBrush", "#0D1117");
            SetBrush(res, "TextMutedBrush", "#57606A");
            SetBrush(res, "TextAccentBrush", "#0969DA");
            SetBrush(res, "TextSubHeaderBrush", "#0550AE");
            SetBrush(res, "ButtonBgBrush", "#F6F8FA");
            SetBrush(res, "ButtonHoverBgBrush", "#E6EBF1");
            SetBrush(res, "TabInactiveBgBrush", "#E6ECF3");
            SetBrush(res, "TabHoverBgBrush", "#D5DFEC");
            SetBrush(res, "GridRowBgBrush", "#FFFFFF");
            SetBrush(res, "GridAltRowBgBrush", "#F6F8FB");
            SetBrush(res, "GridHeaderBgBrush", "#EAEFF7");
            SetBrush(res, "GridLineBrush", "#DDE3EA");
            SetBrush(res, "GridSelectedBgBrush", "#D4E8FF");
            SetBrush(res, "GridSelectedFgBrush", "#0550AE");
        }

        OnThemeChanged?.Invoke(isDark);
    }

    private static void SetBrush(ResourceDictionary res, string key, string hex)
    {
        var color = (System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString(hex);
        res[key] = new SolidColorBrush(color);
    }
}
