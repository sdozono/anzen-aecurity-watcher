namespace AnzenSecurityWatcher.Services;

/// <summary>
/// スキャン間隔・省電力動作モード
/// </summary>
public enum ScanIntervalMode
{
    Fast = 3,         // 高速: 3秒周期 (詳細スキャン: 18秒)
    Standard = 5,     // 標準: 5秒周期 (詳細スキャン: 30秒)
    PowerSaving = 15  // 省電力: 15秒周期 (詳細スキャン: 90秒)
}

/// <summary>
/// アプリケーションのユーザー設定（言語、テーマ、スキャン・プロンプトオプション）
/// </summary>
public class AppSettings
{
    public AppLanguage Language { get; set; } = AppLanguage.English;
    public AppThemeMode ThemeMode { get; set; } = AppThemeMode.System;
    public ScanIntervalMode ScanInterval { get; set; } = ScanIntervalMode.Fast;
    public bool IncludeLoopback { get; set; } = false;
    public bool IncludeListen { get; set; } = false;
    public bool IncludeUdp { get; set; } = true;
    public bool EnableDllSideloadCheck { get; set; } = false;
    public bool MaskPersonalInfo { get; set; } = true;
    public bool DisableOnlineGeoIp { get; set; } = false;
}

/// <summary>
/// 設定ファイル（ui_settings.json）の永続化と読み込みを管理するマネージャー
/// </summary>
public static class SettingsManager
{
    public const string SettingsFileName = "ui_settings.json";
    private static AppSettings? _current;
    private static readonly object _lock = new();

    public static AppSettings Current
    {
        get
        {
            if (_current == null)
            {
                lock (_lock)
                {
                    _current ??= LoadSettings();
                }
            }
            return _current;
        }
    }

    public static AppSettings Load()
    {
        lock (_lock)
        {
            _current = LoadSettings();
            return _current;
        }
    }

    private static AppSettings LoadSettings()
    {
        try
        {
            var loaded = JsonStore.Load<AppSettings>(SettingsFileName);
            return loaded ?? new AppSettings();
        }
        catch
        {
            return new AppSettings();
        }
    }

    public static void Save()
    {
        lock (_lock)
        {
            if (_current != null)
            {
                JsonStore.Save(SettingsFileName, _current);
            }
        }
    }
}
