using System.Collections.Concurrent;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using Timer = System.Threading.Timer;

namespace AnzenSecurityWatcher.Services;

public record GeoIpInfo(
    string CountryCode,
    string CountryName,
    string Flag,
    string Organization,
    string City,
    bool IsPrivateOrLocal,
    bool IsHighAttentionCountry);

public class GeoIpService : IDisposable
{
    private readonly ConcurrentDictionary<string, GeoIpInfo> _cache = new();
    private readonly ConcurrentDictionary<string, byte> _pendingLookups = new();
    private readonly HttpClient _httpClient;
    private readonly string _cacheFilePath;
    private readonly SemaphoreSlim _rateLimitSemaphore = new(2, 2);

    private readonly object _saveLock = new();
    private readonly Timer _debounceTimer;
    private volatile bool _isDirty;
    private DateTime _firstDirtyTime = DateTime.MinValue;
    private bool _disposed;
    private static readonly TimeSpan DebounceDelay = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan MaxDebounceDelay = TimeSpan.FromSeconds(30);

    /// <summary>
    /// オンラインGeoIP照会を無効化するフラグ（オフライン専用モード・外部APIへの通信を遮断）
    /// </summary>
    public bool DisableOnlineLookup { get; set; } = false;

    // 注意・警戒対象としてハイライトしやすい国コード（設定・目安として利用）
    private static readonly HashSet<string> HighAttentionCountries = new(StringComparer.OrdinalIgnoreCase)
    {
        "RU", "CN", "KP", "IR", "BY"
    };

    private static readonly Dictionary<string, (string En, string Zh, string Es, string Ja, string Flag)> CountryMeta = new(StringComparer.OrdinalIgnoreCase)
    {
        ["LOCAL"] = ("Localhost (Internal)", "本地主机 (电脑内部)", "Localhost (Interno)", "ローカルホスト (PC内部)", "🏠"),
        ["LAN"] = ("Local LAN (Private)", "局域网 (家庭/企业内网)", "Red Local LAN", "ローカルLAN (家庭/社内網)", "🏢"),
        ["MCAST"] = ("Multicast / Broadcast", "多播/广播", "Multidifusión / Broadcast", "マルチキャスト/ブロードキャスト", "📡"),
        ["JP"] = ("Japan", "日本", "Japón", "日本", "🇯🇵"),
        ["US"] = ("United States", "美国", "Estados Unidos", "アメリカ", "🇺🇸"),
        ["CN"] = ("China", "中国", "China", "中国", "🇨🇳"),
        ["RU"] = ("Russia", "俄罗斯", "Rusia", "ロシア", "🇷🇺"),
        ["KR"] = ("South Korea", "韩国", "Corea del Sur", "韓国", "🇰🇷"),
        ["TW"] = ("Taiwan", "台湾", "Taiwán", "台湾", "🇹🇼"),
        ["HK"] = ("Hong Kong", "香港", "Hong Kong", "香港", "🇭🇰"),
        ["SG"] = ("Singapore", "新加坡", "Singapur", "シンガポール", "🇸🇬"),
        ["IN"] = ("India", "印度", "India", "インド", "🇮🇳"),
        ["AU"] = ("Australia", "澳大利亚", "Australia", "オーストラリア", "🇦🇺"),
        ["GB"] = ("United Kingdom", "英国", "Reino Unido", "イギリス", "🇬🇧"),
        ["DE"] = ("Germany", "德国", "Alemania", "ドイツ", "🇩🇪"),
        ["FR"] = ("France", "法国", "Francia", "フランス", "🇫🇷"),
        ["NL"] = ("Netherlands", "荷兰", "Países Bajos", "オランダ", "🇳🇱"),
        ["IE"] = ("Ireland", "爱尔兰", "Irlanda", "アイルランド", "🇮🇪"),
        ["SE"] = ("Sweden", "瑞典", "Suecia", "スウェーデン", "🇸🇪"),
        ["FI"] = ("Finland", "芬兰", "Finlandia", "フィンランド", "🇫🇮"),
        ["CH"] = ("Switzerland", "瑞士", "Suiza", "スイス", "🇨🇭"),
        ["CA"] = ("Canada", "加拿大", "Canadá", "カナダ", "🇨🇦"),
        ["BR"] = ("Brazil", "巴西", "Brasil", "ブラジル", "🇧🇷"),
        ["KP"] = ("North Korea", "朝鲜", "Corea del Norte", "北朝鮮", "🇰🇵"),
        ["IR"] = ("Iran", "伊朗", "Irán", "イラン", "🇮🇷"),
        ["BY"] = ("Belarus", "白俄罗斯", "Bielorrusia", "ベラルーシ", "🇧🇾"),
        ["UA"] = ("Ukraine", "乌克兰", "Ucrania", "ウクライナ", "🇺🇦"),
        ["VN"] = ("Vietnam", "越南", "Vietnam", "ベトナム", "🇻🇳"),
        ["ID"] = ("Indonesia", "印度尼西亚", "Indonesia", "インドネシア", "🇮🇩"),
        ["TH"] = ("Thailand", "泰国", "Tailandia", "タイ", "🇹🇭"),
        ["PH"] = ("Philippines", "菲律宾", "Filipinas", "フィリピン", "🇵🇭"),
        ["MY"] = ("Malaysia", "马来西亚", "Malasia", "マレーシア", "🇲🇾"),
        ["IL"] = ("Israel", "以色列", "Israel", "イスラエル", "🇮🇱"),
        ["TR"] = ("Turkey", "土耳其", "Turquía", "トルコ", "🇹🇷"),
        ["ZA"] = ("South Africa", "南非", "Sudáfrica", "南アフリカ", "🇿🇦"),
        ["MX"] = ("Mexico", "墨西哥", "México", "メキシコ", "🇲🇽"),
        ["AR"] = ("Argentina", "阿根廷", "Argentina", "アルゼンチン", "🇦🇷"),
        ["PL"] = ("Poland", "波兰", "Polonia", "ポーランド", "🇵🇱"),
        ["IT"] = ("Italy", "意大利", "Italia", "イタリア", "🇮🇹"),
        ["ES"] = ("Spain", "西班牙", "España", "スペイン", "🇪🇸"),
        ["RO"] = ("Romania", "罗马尼亚", "Rumania", "ルーマニア", "🇷🇴"),
        ["BG"] = ("Bulgaria", "保加利亚", "Bulgaria", "ブルガリア", "🇧🇬"),
        ["CZ"] = ("Czechia", "捷克", "Chequia", "チェコ", "🇨🇿"),
        ["AT"] = ("Austria", "奥地利", "Austria", "オーストリア", "🇦🇹"),
        ["BE"] = ("Belgium", "比利时", "Bélgica", "ベルギー", "🇧🇪"),
        ["DK"] = ("Denmark", "丹麦", "Dinamarca", "デンマーク", "🇩🇰"),
        ["NO"] = ("Norway", "挪威", "Noruega", "ノルウェー", "🇳🇴"),
    };

    public static string GetLocalizedCountryName(string countryCode, string? fallbackName = null)
    {
        if (!string.IsNullOrWhiteSpace(countryCode) && CountryMeta.TryGetValue(countryCode.Trim(), out var meta))
        {
            return Loc.T(meta.En, meta.Zh, meta.Es, meta.Ja);
        }
        return !string.IsNullOrWhiteSpace(fallbackName) ? fallbackName : countryCode;
    }

    public event Action<string, GeoIpInfo>? OnGeoIpResolved;

    public GeoIpService()
    {
        _debounceTimer = new Timer(OnDebounceTimerFired, null, Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);
        _httpClient = new HttpClient { Timeout = TimeSpan.FromSeconds(4) };
        _httpClient.DefaultRequestHeaders.UserAgent.ParseAdd("AnzenSecurityWatcher/1.0");

        string dataDir = JsonStore.DataDir;
        try { Directory.CreateDirectory(dataDir); } catch { }
        _cacheFilePath = Path.Combine(dataDir, "geoip_cache.json");
        DisableOnlineLookup = SettingsManager.Current.DisableOnlineGeoIp;
        LoadCache();
    }

    public GeoIpInfo GetOrResolve(string ipString)
    {
        if (string.IsNullOrWhiteSpace(ipString))
            return new GeoIpInfo("LOCAL", GetLocalizedCountryName("LOCAL"), "⚪", "-", "", true, false);

        if (_cache.TryGetValue(ipString, out var cached))
            return cached with { CountryName = GetLocalizedCountryName(cached.CountryCode, cached.CountryName) };

        // 1. ローカル・プライベートIPの即時判定
        var localCheck = TryClassifyLocalOrPrivate(ipString);
        if (localCheck != null)
        {
            _cache[ipString] = localCheck;
            return localCheck;
        }

        // 2. 内蔵オフラインプレフィックス判定（初期表示用およびオフラインフォールバック用）
        var offlineGuess = ClassifyOfflineHeuristic(ipString);

        // オンラインGeoIPが無効化されている（オフライン専用/エアギャップモード）場合は外部リクエストを行わない
        if (DisableOnlineLookup || SettingsManager.Current.DisableOnlineGeoIp)
        {
            return offlineGuess;
        }

        // 3. バックグラウンドでオンラインGeoIP APIにより正確な国名・ISP・都市名を取得
        if (_pendingLookups.TryAdd(ipString, 1))
        {
            _ = Task.Run(() => LookupOnlineAsync(ipString, offlineGuess));
        }

        return offlineGuess;
    }

    private GeoIpInfo? TryClassifyLocalOrPrivate(string ipString)
    {
        if (!IPAddress.TryParse(ipString, out var ip))
            return new GeoIpInfo("LOCAL", GetLocalizedCountryName("LOCAL"), "🏠", "Local", "", true, false);

        byte[] bytes = ip.GetAddressBytes();
        if (bytes.Length != 4)
        {
            if (IPAddress.IsLoopback(ip) || ip.Equals(IPAddress.IPv6Any) || ip.Equals(IPAddress.IPv6None))
                return new GeoIpInfo("LOCAL", GetLocalizedCountryName("LOCAL"), "🏠", "Loopback", "", true, false);

            if (ip.IsIPv4MappedToIPv6)
                return TryClassifyLocalOrPrivate(ip.MapToIPv4().ToString());

            // IPv6 Link-Local (fe80::/10)
            if (ip.IsIPv6LinkLocal)
                return new GeoIpInfo("LAN", GetLocalizedCountryName("LAN"), "🏢", "Link-Local IPv6 (fe80::/10)", "", true, false);

            // IPv6 Unique Local Address (fc00::/7 -> fc00::/8, fd00::/8)
            if (bytes[0] == 0xfc || bytes[0] == 0xfd)
                return new GeoIpInfo("LAN", GetLocalizedCountryName("LAN"), "🏢", "Unique Local IPv6 (fc00::/7)", "", true, false);

            // IPv6 Multicast (ff00::/8)
            if (ip.IsIPv6Multicast)
                return new GeoIpInfo("MCAST", GetLocalizedCountryName("MCAST"), "📡", "IPv6 Multicast", "", true, false);

            // IPv6 Site-Local (fec0::/10)
            if (ip.IsIPv6SiteLocal)
                return new GeoIpInfo("LAN", GetLocalizedCountryName("LAN"), "🏢", "Site-Local IPv6", "", true, false);

            return null;
        }

        // 0.0.0.0 or 127.x.x.x
        if (bytes[0] == 0 || bytes[0] == 127)
            return new GeoIpInfo("LOCAL", GetLocalizedCountryName("LOCAL"), "🏠", "Loopback", "", true, false);

        // 10.x.x.x
        if (bytes[0] == 10)
            return new GeoIpInfo("LAN", GetLocalizedCountryName("LAN"), "🏢", "Private Network (10.0.0.0/8)", "", true, false);

        // 172.16.x.x - 172.31.x.x
        if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31)
            return new GeoIpInfo("LAN", GetLocalizedCountryName("LAN"), "🏢", "Private Network (172.16.0.0/12)", "", true, false);

        // 192.168.x.x
        if (bytes[0] == 192 && bytes[1] == 168)
            return new GeoIpInfo("LAN", GetLocalizedCountryName("LAN"), "🏢", "Private Network (192.168.0.0/16)", "", true, false);

        // 169.254.x.x (Link-local)
        if (bytes[0] == 169 && bytes[1] == 254)
            return new GeoIpInfo("LAN", GetLocalizedCountryName("LAN"), "🏢", "Link-Local (APIPA)", "", true, false);

        // 100.64.0.0/10 (CGNAT / Tailscale etc.)
        if (bytes[0] == 100 && bytes[1] >= 64 && bytes[1] <= 127)
            return new GeoIpInfo("LAN", GetLocalizedCountryName("LAN"), "🛡️", "Shared Address Space (CGNAT/VPN)", "", true, false);

        // 224.0.0.0+ (Multicast / Broadcast)
        if (bytes[0] >= 224)
            return new GeoIpInfo("MCAST", GetLocalizedCountryName("MCAST"), "📡", "Multicast", "", true, false);

        return null;
    }

    private GeoIpInfo ClassifyOfflineHeuristic(string ipString)
    {
        if (!IPAddress.TryParse(ipString, out var ip))
            return new GeoIpInfo("UNK", Loc.T("Unknown", "未知", "Desconocido", "不明"), "🌐", "Unknown", "", false, false);

        byte[] b = ip.GetAddressBytes();
        if (b.Length != 4)
        {
            if (ip.IsIPv4MappedToIPv6)
                return ClassifyOfflineHeuristic(ip.MapToIPv4().ToString());
            return new GeoIpInfo("UNK", Loc.T("Resolving...", "查询中...", "Consultando...", "照会中..."), "🌐", "IPv6 Network", "", false, false);
        }

        int first = b[0];
        int second = b[1];

        // よく使われる代表的なグローバルIP帯のオフライン即時推定（オンライン解決までの初期値＆オフライン時のフォールバック）
        if ((first == 1 && second == 1) || (first == 1 && second == 0) || first == 104 || first == 172)
            return CreateInfo("US", "Cloudflare / CDN", "");
        if (first == 8 && second == 8)
            return CreateInfo("US", "Google Public DNS", "Mountain View");
        if (first == 142 && second == 250 || (first == 172 && second == 217) || (first == 216 && second == 58))
            return CreateInfo("US", "Google LLC", "");
        if (first == 13 || first == 20 || first == 40 || first == 51 || first == 52 || (first == 204 && second == 79))
            return CreateInfo("US", "Microsoft / Cloud", "Redmond");
        if (first == 140 && second == 82 || (first == 185 && second == 199))
            return CreateInfo("US", "GitHub / Fastly", "San Francisco");
        if (first == 3 || first == 18 || first == 34 || first == 35 || first == 54)
            return CreateInfo("US", "AWS / Google Cloud", "");
        if (first == 126 || first == 133 || first == 153 || first == 60 || first == 61 || first == 114 || first == 118 || first == 122 || first == 210 || first == 219)
            return CreateInfo("JP", "Japan ISP", "Tokyo");
        if (first == 36 || first == 39 || first == 42 || first == 58 || first == 59 || first == 101 || first == 106 || first == 110 || first == 111 || first == 112 || first == 113 || first == 115 || first == 116 || first == 117 || first == 119 || first == 120 || first == 121 || first == 123 || first == 124 || first == 125 || first == 180 || first == 182 || first == 183 || first == 218 || first == 220 || first == 221 || first == 222 || first == 223)
            return CreateInfo("JP", "Asia-Pacific (APNIC)", "");
        if (first == 5 || first == 31 || first == 37 || first == 46 || first == 77 || first == 78 || first == 79 || first == 80 || first == 81 || first == 82 || first == 83 || first == 84 || first == 85 || first == 86 || first == 87 || first == 88 || first == 89 || first == 90 || first == 91 || first == 92 || first == 93 || first == 94 || first == 95 || first == 109 || first == 176 || first == 178 || first == 185 || first == 188 || first == 193 || first == 194 || first == 195 || first == 212 || first == 213 || first == 217)
            return CreateInfo("DE", "European Network (RIPE)", "");

        return CreateInfo("US", "North America / Global (ARIN)", "");
    }

    private async Task LookupOnlineAsync(string ipString, GeoIpInfo fallback)
    {
        // オフライン専用モードの場合は外部通信を行わずに即時終了
        if (DisableOnlineLookup || SettingsManager.Current.DisableOnlineGeoIp)
        {
            _pendingLookups.TryRemove(ipString, out _);
            return;
        }

        await _rateLimitSemaphore.WaitAsync();
        try
        {
            if (DisableOnlineLookup || SettingsManager.Current.DisableOnlineGeoIp)
            {
                return;
            }

            // 1. Primary: ipwho.is (HTTPS, APIキー不要, 無料)
            try
            {
                using var resp = await _httpClient.GetAsync($"https://ipwho.is/{ipString}");
                if (resp.IsSuccessStatusCode)
                {
                    string json = await resp.Content.ReadAsStringAsync();
                    using var doc = JsonDocument.Parse(json);
                    var root = doc.RootElement;
                    if (root.TryGetProperty("success", out var succ) && succ.GetBoolean())
                    {
                        string cc = root.TryGetProperty("country_code", out var ccEl) ? ccEl.GetString() ?? "UNK" : "UNK";
                        string cn = root.TryGetProperty("country", out var cnEl) ? cnEl.GetString() ?? cc : cc;
                        string city = root.TryGetProperty("city", out var cityEl) ? cityEl.GetString() ?? "" : "";
                        string org = "";
                        if (root.TryGetProperty("connection", out var connEl))
                        {
                            string orgName = connEl.TryGetProperty("org", out var oEl) ? oEl.GetString() ?? "" : "";
                            string ispName = connEl.TryGetProperty("isp", out var iEl) ? iEl.GetString() ?? "" : "";
                            org = !string.IsNullOrWhiteSpace(orgName) ? orgName : ispName;
                        }

                        var resolved = CreateInfo(cc, string.IsNullOrWhiteSpace(org) ? cn : org, city, cn);
                        _cache[ipString] = resolved;
                        RequestSaveCache();
                        OnGeoIpResolved?.Invoke(ipString, resolved);
                        return;
                    }
                }
            }
            catch
            {
                // Fallback to secondary API
            }

            // 2. Secondary fallback: freeipapi.com (HTTPS, 暗号化通信, APIキー不要)
            try
            {
                using var resp2 = await _httpClient.GetAsync($"https://freeipapi.com/api/json/{ipString}");
                if (resp2.IsSuccessStatusCode)
                {
                    string json = await resp2.Content.ReadAsStringAsync();
                    using var doc = JsonDocument.Parse(json);
                    var root = doc.RootElement;
                    string cc = root.TryGetProperty("countryCode", out var ccEl) ? ccEl.GetString() ?? "UNK" : "UNK";
                    if (!string.IsNullOrWhiteSpace(cc) && cc != "-")
                    {
                        string cn = root.TryGetProperty("countryName", out var cnEl) ? cnEl.GetString() ?? cc : cc;
                        string city = root.TryGetProperty("cityName", out var cityEl) ? cityEl.GetString() ?? "" : "";
                        string org = root.TryGetProperty("asnOrganization", out var oEl) ? oEl.GetString() ?? "" : "";

                        var resolved = CreateInfo(cc, org, city, cn);
                        _cache[ipString] = resolved;
                        RequestSaveCache();
                        OnGeoIpResolved?.Invoke(ipString, resolved);
                        return;
                    }
                }
            }
            catch
            {
                // Fallback to tertiary API
            }

            // 3. Tertiary fallback: ipapi.co (HTTPS, 暗号化通信, APIキー不要)
            try
            {
                using var resp3 = await _httpClient.GetAsync($"https://ipapi.co/{ipString}/json/");
                if (resp3.IsSuccessStatusCode)
                {
                    string json = await resp3.Content.ReadAsStringAsync();
                    using var doc = JsonDocument.Parse(json);
                    var root = doc.RootElement;
                    if (!root.TryGetProperty("error", out var errEl) || !errEl.GetBoolean())
                    {
                        string cc = root.TryGetProperty("country_code", out var ccEl) ? ccEl.GetString() ?? "UNK" : "UNK";
                        if (!string.IsNullOrWhiteSpace(cc))
                        {
                            string cn = root.TryGetProperty("country_name", out var cnEl) ? cnEl.GetString() ?? cc : cc;
                            string city = root.TryGetProperty("city", out var cityEl) ? cityEl.GetString() ?? "" : "";
                            string org = root.TryGetProperty("org", out var oEl) ? oEl.GetString() ?? "" : "";

                            var resolved = CreateInfo(cc, org, city, cn);
                            _cache[ipString] = resolved;
                            RequestSaveCache();
                            OnGeoIpResolved?.Invoke(ipString, resolved);
                            return;
                        }
                    }
                }
            }
            catch
            {
                // Offline fallback
            }

            // オンライン照会が失敗した場合はオフライン推定結果をキャッシュに格納
            _cache[ipString] = fallback;
            OnGeoIpResolved?.Invoke(ipString, fallback);
        }
        finally
        {
            await Task.Delay(250); // レート制限保護
            _rateLimitSemaphore.Release();
            _pendingLookups.TryRemove(ipString, out _);
        }
    }

    public static GeoIpInfo CreateInfo(string countryCode, string org, string city, string? fallbackCountryName = null)
    {
        string code = string.IsNullOrWhiteSpace(countryCode) ? "UNK" : countryCode.ToUpperInvariant();
        string nameLocalized;
        string flag;

        if (CountryMeta.TryGetValue(code, out var meta))
        {
            nameLocalized = Loc.T(meta.En, meta.Zh, meta.Es, meta.Ja);
            flag = meta.Flag;
        }
        else
        {
            nameLocalized = !string.IsNullOrWhiteSpace(fallbackCountryName) ? fallbackCountryName : code;
            flag = GetFlagEmoji(code);
        }

        bool isLocal = code is "LOCAL" or "LAN" or "MCAST";
        bool isHighAttention = HighAttentionCountries.Contains(code);
        return new GeoIpInfo(code, nameLocalized, flag, org, city, isLocal, isHighAttention);
    }

    private static string GetFlagEmoji(string countryCode)
    {
        if (string.IsNullOrWhiteSpace(countryCode) || countryCode.Length != 2)
            return "🌐";
        char c1 = char.ToUpperInvariant(countryCode[0]);
        char c2 = char.ToUpperInvariant(countryCode[1]);
        if (c1 < 'A' || c1 > 'Z' || c2 < 'A' || c2 > 'Z')
            return "🌐";
        return string.Concat(
            char.ConvertFromUtf32(c1 - 'A' + 0x1F1E6),
            char.ConvertFromUtf32(c2 - 'A' + 0x1F1E6));
    }

    private void LoadCache()
    {
        lock (_saveLock)
        {
            try
            {
                if (!File.Exists(_cacheFilePath)) return;
                string json = File.ReadAllText(_cacheFilePath);
                var dict = JsonSerializer.Deserialize<Dictionary<string, GeoIpInfo>>(json);
                if (dict != null)
                {
                    foreach (var kv in dict)
                    {
                        _cache[kv.Key] = kv.Value;
                    }
                }
            }
            catch
            {
                // Ignore cache read error
            }
        }
    }

    private void OnDebounceTimerFired(object? state)
    {
        SaveCacheSafe();
    }

    private void RequestSaveCache()
    {
        if (_disposed) return;

        lock (_saveLock)
        {
            if (_disposed) return;

            if (!_isDirty)
            {
                _isDirty = true;
                _firstDirtyTime = DateTime.UtcNow;
                try
                {
                    _debounceTimer.Change(DebounceDelay, Timeout.InfiniteTimeSpan);
                }
                catch (ObjectDisposedException) { }
            }
            else
            {
                // 連続解決時も過度な延期を防ぐ（初回変更から30秒未満なら5秒後に再延長）
                if (DateTime.UtcNow - _firstDirtyTime < MaxDebounceDelay)
                {
                    try
                    {
                        _debounceTimer.Change(DebounceDelay, Timeout.InfiniteTimeSpan);
                    }
                    catch (ObjectDisposedException) { }
                }
            }
        }
    }

    public void FlushCache()
    {
        SaveCacheSafe();
    }

    public void SaveCacheSafe()
    {
        if (!_isDirty) return;

        lock (_saveLock)
        {
            if (!_isDirty) return;

            try
            {
                var snapshot = _cache.ToDictionary(k => k.Key, v => v.Value);
                string json = JsonSerializer.Serialize(snapshot, new JsonSerializerOptions { WriteIndented = true });

                string dir = Path.GetDirectoryName(_cacheFilePath) ?? "";
                if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
                {
                    Directory.CreateDirectory(dir);
                }

                string tempFilePath = _cacheFilePath + ".tmp";
                File.WriteAllText(tempFilePath, json);
                File.Move(tempFilePath, _cacheFilePath, overwrite: true);

                _isDirty = false;
                _firstDirtyTime = DateTime.MinValue;
            }
            catch
            {
                // Ignore cache write error
            }
        }
    }

    public void Dispose()
    {
        if (_disposed) return;

        lock (_saveLock)
        {
            if (_disposed) return;
            _disposed = true;
        }

        try
        {
            _debounceTimer.Dispose();
        }
        catch { }

        SaveCacheSafe();

        _rateLimitSemaphore.Dispose();
        _httpClient.Dispose();
        GC.SuppressFinalize(this);
    }
}
