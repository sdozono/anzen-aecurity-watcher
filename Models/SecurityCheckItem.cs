using AnzenSecurityWatcher.Services;

namespace AnzenSecurityWatcher.Models;

public enum CheckResult
{
    Pass,     // 良好
    Warning,  // 一部不十分
    Fail,     // 危険・無効
    Unknown   // 取得不可（権限不足など）→ スコア計算から除外
}

/// <summary>
/// 安全スコア診断の 1 項目
/// </summary>
public class SecurityCheckItem
{
    public string Id { get; set; } = "";
    public string Name { get; set; } = "";
    public CheckResult Result { get; set; } = CheckResult.Unknown;
    public int Weight { get; set; }
    public string StatusText { get; set; } = "";
    public string Advice { get; set; } = "";
    /// <summary>「設定を開く」で起動するコマンド / URI（空なら非表示）</summary>
    public string FixCommand { get; set; } = "";

    /// <summary>このチェックで獲得した点（Warning は半分）</summary>
    public double EarnedPoints => Result switch
    {
        CheckResult.Pass => Weight,
        CheckResult.Warning => Weight / 2.0,
        _ => 0
    };

    public bool HasFix => !string.IsNullOrWhiteSpace(FixCommand) && Result is CheckResult.Fail or CheckResult.Warning;

    public string ResultBadge => Result switch
    {
        CheckResult.Pass => Loc.T("✅ Pass", "✅ 良好", "✅ Óptimo", "✅ 良好"),
        CheckResult.Warning => Loc.T("⚠️ Warning", "⚠️ 需改进", "⚠️ Mejorable", "⚠️ 要改善"),
        CheckResult.Fail => Loc.T("❌ Risk", "❌ 危险", "❌ Peligro", "❌ 危険"),
        _ => Loc.T("❔ Unknown", "❔ 无法获取", "❔ Desconocido", "❔ 取得不可")
    };

    public string WeightText => Result == CheckResult.Unknown ? $"-/{Weight}" : $"{EarnedPoints:0.#}/{Weight}";
}

public class SecurityPostureReport
{
    public List<SecurityCheckItem> Checks { get; set; } = new();
    public DateTime EvaluatedAt { get; set; } = DateTime.Now;

    public int Score
    {
        get
        {
            var evaluated = Checks.Where(c => c.Result != CheckResult.Unknown).ToList();
            double possible = evaluated.Sum(c => c.Weight);
            if (possible <= 0) return 0;
            return (int)Math.Round(evaluated.Sum(c => c.EarnedPoints) / possible * 100);
        }
    }

    public string Grade => Score switch
    {
        >= 90 => "A",
        >= 75 => "B",
        >= 60 => "C",
        >= 40 => "D",
        _ => "E"
    };

    public string GradeComment => Score switch
    {
        >= 90 => Loc.T("Very secure configuration", "非常安全的设置", "Configuración muy segura", "とても安全な設定です"),
        >= 75 => Loc.T("Generally secure", "总体安全", "Generalmente seguro", "おおむね安全です"),
        >= 60 => Loc.T("Some improvements recommended", "存在几处需改进项", "Se recomiendan algunas mejoras", "いくつか改善点があります"),
        >= 40 => Loc.T("Risky settings detected", "存在危险设置", "Configuración riesgosa detectada", "危険な設定があります"),
        _ => Loc.T("Immediate action required", "需要立即采取措施", "Se requiere acción inmediata", "早急な対策が必要です")
    };
}
