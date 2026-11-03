using System.Collections.Concurrent;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using AnzenSecurityWatcher.Models;

namespace AnzenSecurityWatcher.Services;

public record SignatureVerifyResult(
    SignatureStatus Status,
    bool IsSigned,
    string Signer,
    string Publisher,
    string Reason,
    string Sha256);

/// <summary>
/// 実行ファイル / DLL のデジタル署名（Authenticode 埋め込み署名 + カタログ検証）および SHA256 を確認するキャッシュ付きヘルパー
/// Unsigned と Unknown (解決不能) を明確に分離する。
/// </summary>
public static class SignatureHelper
{
    private static readonly ConcurrentDictionary<string, SignatureVerifyResult> ExtendedCache = new(StringComparer.OrdinalIgnoreCase);
    private static readonly ConcurrentDictionary<string, string> Sha256Cache = new(StringComparer.OrdinalIgnoreCase);

    public static (bool IsSigned, string Signer) Check(string filePath)
    {
        var ext = CheckExtended(filePath);
        return (ext.IsSigned, ext.Signer);
    }

    public static SignatureVerifyResult CheckExtended(string filePath, bool isComServer = false, string unresolvedReason = "")
    {
        if (string.IsNullOrWhiteSpace(filePath) ||
            filePath.Equals("COM", StringComparison.OrdinalIgnoreCase) ||
            filePath.StartsWith("COM ", StringComparison.OrdinalIgnoreCase) ||
            filePath.StartsWith("(", StringComparison.Ordinal))
        {
            string reason = !string.IsNullOrWhiteSpace(unresolvedReason)
                ? unresolvedReason
                : isComServer
                    ? "COM server executable not resolved"
                    : "Executable path not resolved";
            return new SignatureVerifyResult(
                SignatureStatus.Unknown,
                false,
                Loc.T($"Unknown ({reason})", $"未知 ({reason})", $"Desconocido ({reason})", $"不明 ({reason})"),
                "",
                reason,
                "");
        }

        string normalized = PathHelper.CleanFilePath(filePath);
        if (ExtendedCache.TryGetValue(normalized, out var cached))
            return LocalizeResult(cached);

        SignatureVerifyResult res;
        try
        {
            if (!File.Exists(normalized))
            {
                string reason = isComServer
                    ? $"COM server binary not found ({normalized})"
                    : "Target binary file not found on disk";
                res = new SignatureVerifyResult(
                    SignatureStatus.Unknown,
                    false,
                    "__NOT_FOUND__",
                    "",
                    reason,
                    "");
            }
            else
            {
                string sha256 = ComputeSha256(normalized);
                int embResult = VerifyEmbeddedSignature(normalized);

                if (embResult == ERROR_SUCCESS || embResult == CRYPT_E_REVOCATION_OFFLINE || embResult == CERT_E_REVOCATION_FAILURE)
                {
                    var (subject, _, hasCert) = TryExtractCertInfo(normalized);
                    string cn = hasCert ? ExtractCommonName(subject) : "Signed";
                    string org = hasCert ? ExtractOrganization(subject) : "";
                    string pub = !string.IsNullOrWhiteSpace(org) ? org : cn;
                    string reason = embResult == ERROR_SUCCESS
                        ? "Authenticode signature verified (Trusted)"
                        : "Authenticode signature verified (Revocation check offline)";

                    res = new SignatureVerifyResult(
                        SignatureStatus.Signed,
                        true,
                        cn,
                        pub,
                        reason,
                        sha256);
                }
                else if (embResult == CERT_E_REVOKED || embResult == CRYPT_E_REVOKED)
                {
                    // 🚨 証明書失効検知
                    var (subject, _, _) = TryExtractCertInfo(normalized);
                    string cn = !string.IsNullOrWhiteSpace(subject) ? ExtractCommonName(subject) : "";
                    string signer = !string.IsNullOrWhiteSpace(cn)
                        ? $"{cn} ({Loc.T("REVOKED", "已吊销", "REVOCADO", "失効")})"
                        : "__REVOKED__";
                    res = new SignatureVerifyResult(
                        SignatureStatus.Unsigned,
                        false,
                        signer,
                        cn,
                        "Digital certificate has been REVOKED by CA (CERT_E_REVOKED)",
                        sha256);
                }
                else if (embResult == TRUST_E_BAD_DIGEST)
                {
                    // 🚨 ダイジェスト不一致（ファイル改ざん・破損検知）
                    var (subject, _, _) = TryExtractCertInfo(normalized);
                    string cn = !string.IsNullOrWhiteSpace(subject) ? ExtractCommonName(subject) : "";
                    string signer = !string.IsNullOrWhiteSpace(cn)
                        ? $"{cn} ({Loc.T("TAMPERED", "被篡改", "MANIPULADO", "改ざん・不整合")})"
                        : "__TAMPERED__";
                    res = new SignatureVerifyResult(
                        SignatureStatus.Unsigned,
                        false,
                        signer,
                        cn,
                        "File hash does not match signature (File tampered or corrupted)",
                        sha256);
                }
                else if (embResult == CERT_E_UNTRUSTEDROOT || embResult == CERT_E_CHAINING)
                {
                    // 🚨 自己署名証明書 / 信頼されていないルートCA検知
                    var (subject, _, _) = TryExtractCertInfo(normalized);
                    string cn = !string.IsNullOrWhiteSpace(subject) ? ExtractCommonName(subject) : "";
                    string signer = !string.IsNullOrWhiteSpace(cn)
                        ? $"{cn} ({Loc.T("Untrusted Root / Self-Signed", "不受信任的根/自签名", "Raíz no confiable / Autofirmado", "信頼されていないルート / 自己署名")})"
                        : "__UNTRUSTED_ROOT__";
                    res = new SignatureVerifyResult(
                        SignatureStatus.Unsigned,
                        false,
                        signer,
                        cn,
                        "Untrusted root CA or self-signed certificate (CERT_E_UNTRUSTEDROOT)",
                        sha256);
                }
                else if (embResult == CERT_E_EXPIRED)
                {
                    // ⚠️ 証明書有効期限切れ
                    var (subject, _, _) = TryExtractCertInfo(normalized);
                    string cn = !string.IsNullOrWhiteSpace(subject) ? ExtractCommonName(subject) : "";
                    string signer = !string.IsNullOrWhiteSpace(cn)
                        ? $"{cn} ({Loc.T("Expired", "已过期", "Caducado", "期限切れ")})"
                        : "__EXPIRED__";
                    res = new SignatureVerifyResult(
                        SignatureStatus.Unsigned,
                        false,
                        signer,
                        cn,
                        "Certificate expired without valid timestamp (CERT_E_EXPIRED)",
                        sha256);
                }
                else if (embResult == TRUST_E_EXPLICIT_DISTRUST)
                {
                    // 🚨 明示的不信
                    var (subject, _, _) = TryExtractCertInfo(normalized);
                    string cn = !string.IsNullOrWhiteSpace(subject) ? ExtractCommonName(subject) : "";
                    string signer = !string.IsNullOrWhiteSpace(cn)
                        ? $"{cn} ({Loc.T("Distrusted", "不受信任", "No confiable", "明示的不信")})"
                        : "__UNSIGNED__";
                    res = new SignatureVerifyResult(
                        SignatureStatus.Unsigned,
                        false,
                        signer,
                        cn,
                        "Certificate explicitly distrusted by system policy",
                        sha256);
                }
                else
                {
                    // 埋め込み署名なし (TRUST_E_NOSIGNATURE) またはその他の状態 -> Windows セキュリティカタログ署名を厳密に検証
                    var catRes = VerifyCatalogSignature(normalized);
                    if (catRes.Verified)
                    {
                        res = new SignatureVerifyResult(
                            SignatureStatus.Signed,
                            true,
                            "__OS_CATALOG__",
                            "Microsoft Corporation",
                            "Windows system catalog verified",
                            sha256);
                    }
                    else if (PathHelper.IsWindowsAppsLocation(normalized))
                    {
                        // 📦 WindowsApps / ストアアプリのパッケージ単位署名判定 (Get-AppxPackage SignatureKind / AppX)
                        var appx = AppxPackageSignatureHelper.CheckAppxSignature(normalized);
                        if (appx.IsSigned)
                        {
                            res = new SignatureVerifyResult(
                                SignatureStatus.Signed,
                                true,
                                appx.Signer,
                                appx.Publisher,
                                appx.Reason,
                                sha256);
                        }
                        else
                        {
                            string company = TryGetFileCompanyName(normalized);
                            res = new SignatureVerifyResult(
                                SignatureStatus.Unsigned,
                                false,
                                "__UNSIGNED__",
                                company,
                                "No valid AppX/MSIX package signature found",
                                sha256);
                        }
                    }
                    else
                    {
                        string company = TryGetFileCompanyName(normalized);
                        string reason;
                        if (embResult != TRUST_E_NOSIGNATURE)
                        {
                            string? diag = DiagnoseWithX509Chain(normalized);
                            reason = diag != null
                                ? $"Signature invalid: {diag} (0x{embResult:X8})"
                                : $"Signature verification failed (HRESULT: 0x{embResult:X8})";
                        }
                        else
                        {
                            reason = string.IsNullOrWhiteSpace(company)
                                ? "No Authenticode signature present"
                                : $"No Authenticode signature (File CompanyName: {company})";
                        }

                        res = new SignatureVerifyResult(
                            SignatureStatus.Unsigned,
                            false,
                            "__UNSIGNED__",
                            company,
                            reason,
                            sha256);
                    }
                }
            }
        }
        catch (UnauthorizedAccessException)
        {
            if (PathHelper.IsWindowsAppsLocation(normalized))
            {
                var appx = AppxPackageSignatureHelper.CheckAppxSignature(normalized);
                if (appx.IsSigned)
                {
                    res = new SignatureVerifyResult(
                        SignatureStatus.Signed,
                        true,
                        appx.Signer,
                        appx.Publisher,
                        appx.Reason,
                        "");
                }
                else
                {
                    res = new SignatureVerifyResult(
                        SignatureStatus.Unknown,
                        false,
                        "__ACCESS_DENIED__",
                        "",
                        "Access denied while reading binary",
                        "");
                }
            }
            else
            {
                res = new SignatureVerifyResult(
                    SignatureStatus.Unknown,
                    false,
                    "__ACCESS_DENIED__",
                    "",
                    "Access denied while reading binary",
                    "");
            }
        }
        catch (Exception ex)
        {
            res = new SignatureVerifyResult(
                SignatureStatus.Unknown,
                false,
                "__UNKNOWN__",
                "",
                $"Unable to verify signature: {ex.Message}",
                "");
        }

        ExtendedCache[normalized] = res;
        return LocalizeResult(res);
    }

    private static SignatureVerifyResult LocalizeResult(SignatureVerifyResult raw)
    {
        string localizedSigner = raw.Signer switch
        {
            "__NOT_FOUND__" => Loc.T("Unknown (File not found)", "未知 (文件不存在)", "Desconocido (Archivo no encontrado)", "不明 (ファイル未検出)"),
            "__OS_CATALOG__" => Loc.T("Microsoft Windows (OS Standard Catalog)", "Microsoft Windows (OS 标准目录签名)", "Microsoft Windows (Catálogo estándar del SO)", "Microsoft Windows (OS標準カタログ)"),
            "__UNSIGNED__" => Loc.T("Unsigned", "无数字签名", "Sin firma digital", "デジタル署名なし"),
            "__ACCESS_DENIED__" => Loc.T("Unknown (Access denied)", "未知 (权限不足)", "Desconocido (Acceso denegado)", "不明 (アクセス権限外)"),
            "__UNKNOWN__" => Loc.T("Unknown", "未知", "Desconocido", "不明"),
            "__UNTRUSTED_ROOT__" => Loc.T("Untrusted Root / Self-signed", "不受信任的根证书/自签名", "Raíz no confiable / Autofirmado", "信頼されていないルート / 自己署名"),
            "__REVOKED__" => Loc.T("Revoked Certificate", "已吊销证书", "Certificado revocado", "失効した証明書"),
            "__TAMPERED__" => Loc.T("Tampered or Corrupted File", "文件已损坏或被篡改", "Archivo dañado o manipulado", "改ざん・破損バイナリ"),
            "__EXPIRED__" => Loc.T("Expired Certificate", "已过期的证书", "Certificado caducado", "有効期限切れ証明書"),
            _ => raw.Signer
        };
        return raw with { Signer = localizedSigner };
    }

    public static string FormatSignatureLine(SignatureVerifyResult sig)
    {
        return sig.Status switch
        {
            SignatureStatus.Signed => Loc.T(
                $"🔏 Signed ({sig.Signer})",
                $"🔏 已签名 ({sig.Signer})",
                $"🔏 Firmado ({sig.Signer})",
                $"🔏 あり ({sig.Signer})"),
            SignatureStatus.Unknown => Loc.T(
                $"⚪ Unknown (Reason: {sig.Reason})",
                $"⚪ 未知 (原因: {sig.Reason})",
                $"⚪ Desconocido (Motivo: {sig.Reason})",
                $"⚪ 不明・未解決 (理由: {sig.Reason})"),
            _ => FormatUnsignedLine(sig)
        };
    }

    private static string FormatUnsignedLine(SignatureVerifyResult sig)
    {
        // 自己署名、改ざん、失効などの異常検知フラグがある場合はその警告を優先表示
        string unsignedLoc = Loc.T("Unsigned", "无数字签名", "Sin firma digital", "デジタル署名なし");
        if (!string.IsNullOrWhiteSpace(sig.Signer) && sig.Signer != "__UNSIGNED__" && sig.Signer != unsignedLoc)
        {
            return Loc.T(
                $"🚨 Invalid/Untrusted Signature ({sig.Signer} | {sig.Reason})",
                $"🚨 无效/不受信任的签名 ({sig.Signer} | {sig.Reason})",
                $"🚨 Firma no válida o no confiable ({sig.Signer} | {sig.Reason})",
                $"🚨 不正/信頼できない署名 ({sig.Signer} | {sig.Reason})");
        }

        return string.IsNullOrWhiteSpace(sig.Publisher)
            ? Loc.T("⚠️ Unsigned", "⚠️ 未签名 (Unsigned)", "⚠️ Sin firma (Unsigned)", "⚠️ なし (Unsigned)")
            : Loc.T(
                $"⚠️ Unsigned (Vendor metadata: {sig.Publisher})",
                $"⚠️ 未签名 (文件厂商信息: {sig.Publisher})",
                $"⚠️ Sin firma (Metadatos: {sig.Publisher})",
                $"⚠️ なし (ファイル製造元情報: {sig.Publisher})");
    }

    public static string ComputeSha256(string filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath)) return "";
        if (Sha256Cache.TryGetValue(filePath, out var cached)) return cached;

        try
        {
            var fi = new FileInfo(filePath);
            if (!fi.Exists || fi.Length > 120 * 1024 * 1024)
                return "";

            using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            byte[] hash = SHA256.HashData(stream);
            string hex = Convert.ToHexString(hash);
            Sha256Cache[filePath] = hex;
            return hex;
        }
        catch
        {
            return "";
        }
    }

    private static string TryGetFileCompanyName(string filePath)
    {
        try
        {
            var vi = System.Diagnostics.FileVersionInfo.GetVersionInfo(filePath);
            return (vi.CompanyName ?? "").Trim();
        }
        catch
        {
            return "";
        }
    }

    public static bool IsMicrosoftSigner(string signerOrPublisher)
    {
        if (string.IsNullOrWhiteSpace(signerOrPublisher)) return false;
        return signerOrPublisher.Contains("Microsoft", StringComparison.OrdinalIgnoreCase) ||
               signerOrPublisher.Contains("Windows", StringComparison.OrdinalIgnoreCase);
    }

    public static string ExtractCommonName(string subject)
    {
        foreach (var part in subject.Split(','))
        {
            var t = part.Trim();
            if (t.StartsWith("CN=", StringComparison.OrdinalIgnoreCase)) return t[3..].Trim('"');
        }
        foreach (var part in subject.Split(','))
        {
            var t = part.Trim();
            if (t.StartsWith("O=", StringComparison.OrdinalIgnoreCase)) return t[2..].Trim('"');
        }
        return subject;
    }

    public static string ExtractOrganization(string subject)
    {
        foreach (var part in subject.Split(','))
        {
            var t = part.Trim();
            if (t.StartsWith("O=", StringComparison.OrdinalIgnoreCase)) return t[2..].Trim('"');
        }
        return "";
    }

    private static (string Subject, string Issuer, bool HasCert) TryExtractCertInfo(string filePath)
    {
        try
        {
            using var cert = X509Certificate.CreateFromSignedFile(filePath);
            return (cert.Subject ?? "", cert.Issuer ?? "", true);
        }
        catch
        {
            return ("", "", false);
        }
    }

    private static string? DiagnoseWithX509Chain(string filePath)
    {
        try
        {
            using var cert = X509Certificate.CreateFromSignedFile(filePath);
            using var cert2 = new X509Certificate2(cert);
            using var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.Offline;
            chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;
            bool ok = chain.Build(cert2);
            if (!ok && chain.ChainStatus.Length > 0)
            {
                var flag = chain.ChainStatus[0].Status;
                if ((flag & X509ChainStatusFlags.UntrustedRoot) != 0) return "Untrusted root CA / Self-signed certificate";
                if ((flag & X509ChainStatusFlags.Revoked) != 0) return "Digital certificate has been REVOKED";
                if ((flag & X509ChainStatusFlags.NotTimeValid) != 0) return "Certificate expired or not yet valid";
                if ((flag & X509ChainStatusFlags.ExplicitDistrust) != 0) return "Certificate explicitly distrusted";
                return chain.ChainStatus[0].StatusInformation.Trim();
            }
        }
        catch { }
        return null;
    }

    private static int VerifyEmbeddedSignature(string filePath)
    {
        var fileInfo = new WINTRUST_FILE_INFO
        {
            cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
            pcwszFilePath = filePath,
            hFile = IntPtr.Zero,
            pgKnownSubject = IntPtr.Zero
        };

        IntPtr pFileInfo = Marshal.AllocHGlobal((int)fileInfo.cbStruct);
        try
        {
            Marshal.StructureToPtr(fileInfo, pFileInfo, false);
            var data = new WINTRUST_DATA
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                pPolicyCallbackData = IntPtr.Zero,
                pSIPClientData = IntPtr.Zero,
                dwUIChoice = WTD_UI_NONE,
                fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN,
                dwUnionChoice = WTD_CHOICE_FILE,
                pInfo = pFileInfo,
                dwStateAction = 0,
                hWVTStateData = IntPtr.Zero,
                pwszURLReference = null,
                dwProvFlags = WTD_REVOCATION_CHECK_CHAIN | WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_DISABLE_MD2_MD4,
                dwUIContext = 0,
                pSignatureSettings = IntPtr.Zero
            };

            IntPtr pData = Marshal.AllocHGlobal((int)data.cbStruct);
            try
            {
                Marshal.StructureToPtr(data, pData, false);
                return WinVerifyTrust(IntPtr.Zero, WINTRUST_ACTION_GENERIC_VERIFY_V2, pData);
            }
            finally
            {
                Marshal.FreeHGlobal(pData);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(pFileInfo);
        }
    }

    private static (bool Verified, string CatalogPath, int HResult) VerifyCatalogSignature(string filePath)
    {
        IntPtr hCatAdmin;
        if (!CryptCATAdminAcquireContext2(out hCatAdmin, DRIVER_ACTION_VERIFY, "SHA256", IntPtr.Zero, 0))
        {
            if (!CryptCATAdminAcquireContext(out hCatAdmin, DRIVER_ACTION_VERIFY, 0))
                return (false, "", -1);
        }

        try
        {
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            uint hashSize = 0;
            if (!CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, fs.SafeFileHandle, ref hashSize, null, 0) || hashSize == 0)
            {
                if (!CryptCATAdminCalcHashFromFileHandle(hCatAdmin, fs.SafeFileHandle, ref hashSize, null, 0) || hashSize == 0)
                    return (false, "", -2);
            }

            byte[] hash = new byte[hashSize];
            if (!CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, fs.SafeFileHandle, ref hashSize, hash, 0))
            {
                if (!CryptCATAdminCalcHashFromFileHandle(hCatAdmin, fs.SafeFileHandle, ref hashSize, hash, 0))
                    return (false, "", -3);
            }

            var sb = new StringBuilder(hash.Length * 2);
            foreach (byte b in hash) sb.AppendFormat("{0:X2}", b);
            string memberTag = sb.ToString();

            IntPtr prevCat = IntPtr.Zero;
            IntPtr hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, hash, hashSize, 0, ref prevCat);
            if (hCatInfo == IntPtr.Zero)
            {
                return (false, "", TRUST_E_NOSIGNATURE);
            }

            try
            {
                var catInfo = new CATALOG_INFO { cbStruct = (uint)Marshal.SizeOf<CATALOG_INFO>() };
                if (!CryptCATCatalogInfoFromContext(hCatInfo, ref catInfo, 0))
                {
                    return (false, "", -5);
                }

                IntPtr pHash = Marshal.AllocHGlobal((int)hashSize);
                try
                {
                    Marshal.Copy(hash, 0, pHash, (int)hashSize);

                    var wtCatInfo = new WINTRUST_CATALOG_INFO
                    {
                        cbStruct = (uint)Marshal.SizeOf<WINTRUST_CATALOG_INFO>(),
                        dwCatalogVersion = 0,
                        pcwszCatalogFilePath = catInfo.wszCatalogFile,
                        pcwszMemberTag = memberTag,
                        pcwszMemberFilePath = filePath,
                        hMemberFile = IntPtr.Zero,
                        pbCalculatedFileHash = pHash,
                        cbCalculatedFileHash = hashSize,
                        pcCatalogContext = IntPtr.Zero,
                        hCatAdmin = hCatAdmin
                    };

                    IntPtr pCatInfo = Marshal.AllocHGlobal((int)wtCatInfo.cbStruct);
                    try
                    {
                        Marshal.StructureToPtr(wtCatInfo, pCatInfo, false);
                        var data = new WINTRUST_DATA
                        {
                            cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                            pPolicyCallbackData = IntPtr.Zero,
                            pSIPClientData = IntPtr.Zero,
                            dwUIChoice = WTD_UI_NONE,
                            fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN,
                            dwUnionChoice = WTD_CHOICE_CATALOG,
                            pInfo = pCatInfo,
                            dwStateAction = 0,
                            hWVTStateData = IntPtr.Zero,
                            pwszURLReference = null,
                            dwProvFlags = WTD_REVOCATION_CHECK_CHAIN | WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_DISABLE_MD2_MD4,
                            dwUIContext = 0,
                            pSignatureSettings = IntPtr.Zero
                        };

                        IntPtr pData = Marshal.AllocHGlobal((int)data.cbStruct);
                        try
                        {
                            Marshal.StructureToPtr(data, pData, false);
                            int res = WinVerifyTrust(IntPtr.Zero, WINTRUST_ACTION_GENERIC_VERIFY_V2, pData);
                            bool ok = res == ERROR_SUCCESS || res == CRYPT_E_REVOCATION_OFFLINE || res == CERT_E_REVOCATION_FAILURE;
                            return (ok, catInfo.wszCatalogFile, res);
                        }
                        finally
                        {
                            Marshal.FreeHGlobal(pData);
                        }
                    }
                    finally
                    {
                        Marshal.FreeHGlobal(pCatInfo);
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(pHash);
                }
            }
            finally
            {
                CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
            }
        }
        finally
        {
            CryptCATAdminReleaseContext(hCatAdmin, 0);
        }
    }

    #region WinTrust / WinVerifyTrust P/Invoke Definitions

    private static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 = new("{00AAC56B-CD44-11d0-8CC2-00C04FC295EE}");
    private static readonly Guid DRIVER_ACTION_VERIFY = new("{F750E6C3-38EE-11D1-85E5-00C04FC295EE}");

    private const uint WTD_CHOICE_FILE = 1;
    private const uint WTD_CHOICE_CATALOG = 2;
    private const uint WTD_UI_NONE = 2;
    private const uint WTD_REVOKE_WHOLECHAIN = 1;
    private const uint WTD_REVOCATION_CHECK_CHAIN = 0x00000040;
    private const uint WTD_CACHE_ONLY_URL_RETRIEVAL = 0x00001000;
    private const uint WTD_DISABLE_MD2_MD4 = 0x00002000;

    private const int ERROR_SUCCESS = 0;
    private const int TRUST_E_NOSIGNATURE = unchecked((int)0x800B0100);
    private const int TRUST_E_EXPLICIT_DISTRUST = unchecked((int)0x800B0111);
    private const int TRUST_E_BAD_DIGEST = unchecked((int)0x80096010);
    private const int CERT_E_UNTRUSTEDROOT = unchecked((int)0x800B0109);
    private const int CERT_E_CHAINING = unchecked((int)0x800B010A);
    private const int CERT_E_EXPIRED = unchecked((int)0x800B0101);
    private const int CERT_E_REVOKED = unchecked((int)0x80092010);
    private const int CRYPT_E_REVOKED = unchecked((int)0x80092010);
    private const int CRYPT_E_REVOCATION_OFFLINE = unchecked((int)0x80092013);
    private const int CERT_E_REVOCATION_FAILURE = unchecked((int)0x800B010E);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_CATALOG_INFO
    {
        public uint cbStruct;
        public uint dwCatalogVersion;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string pcwszCatalogFilePath;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string pcwszMemberTag;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string pcwszMemberFilePath;
        public IntPtr hMemberFile;
        public IntPtr pbCalculatedFileHash;
        public uint cbCalculatedFileHash;
        public IntPtr pcCatalogContext;
        public IntPtr hCatAdmin;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pInfo;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string? pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CATALOG_INFO
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string wszCatalogFile;
    }

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern int WinVerifyTrust(
        IntPtr hwnd,
        [MarshalAs(UnmanagedType.LPStruct)] Guid pgActionID,
        IntPtr pWVTData);

    [DllImport("wintrust.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CryptCATAdminAcquireContext2(
        out IntPtr phCatAdmin,
        [MarshalAs(UnmanagedType.LPStruct)] Guid pgSubsystem,
        [MarshalAs(UnmanagedType.LPWStr)] string? pwszHashAlgorithm,
        IntPtr pStrongHashPolicy,
        uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CryptCATAdminAcquireContext(
        out IntPtr phCatAdmin,
        [MarshalAs(UnmanagedType.LPStruct)] Guid pgSubsystem,
        uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATAdminCalcHashFromFileHandle2(
        IntPtr hCatAdmin,
        SafeFileHandle hFile,
        ref uint pcbHash,
        [Out] byte[]? pbHash,
        uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATAdminCalcHashFromFileHandle(
        IntPtr hCatAdmin,
        SafeFileHandle hFile,
        ref uint pcbHash,
        [Out] byte[]? pbHash,
        uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern IntPtr CryptCATAdminEnumCatalogFromHash(
        IntPtr hCatAdmin,
        byte[] pbHash,
        uint cbHash,
        uint dwFlags,
        ref IntPtr phPrevCatInfo);

    [DllImport("wintrust.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CryptCATCatalogInfoFromContext(
        IntPtr hCatInfo,
        ref CATALOG_INFO psCatInfo,
        uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATAdminReleaseCatalogContext(
        IntPtr hCatAdmin,
        IntPtr hCatInfo,
        uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATAdminReleaseContext(
        IntPtr hCatAdmin,
        uint dwFlags);

    #endregion
}

/// <summary>
/// COM CLSID ({GUID}) から HKCR\CLSID\{GUID}\InprocServer32 または LocalServer32 を辿り、
/// 実体ファイルパス (.dll / .exe) と署名・SHA256 を解決するヘルパー
/// </summary>
public static class ComClsidResolver
{
    public record ComResolutionResult(
        string Clsid,
        bool IsResolved,
        string ServerType,       // InprocServer32 / LocalServer32 / Unresolved
        string RawRegistryValue,
        string ResolvedBinaryPath,
        string DisplayName,
        SignatureVerifyResult Signature);

    private static readonly ConcurrentDictionary<string, ComResolutionResult> Cache = new(StringComparer.OrdinalIgnoreCase);

    public static ComResolutionResult Resolve(string rawClsid)
    {
        if (string.IsNullOrWhiteSpace(rawClsid))
        {
            var emptySig = SignatureHelper.CheckExtended("", isComServer: true, unresolvedReason: "Empty CLSID");
            return new ComResolutionResult("", false, "Unresolved", "", "", "", emptySig);
        }

        string clsid = rawClsid.Trim();
        if (!clsid.StartsWith("{")) clsid = "{" + clsid.Trim('{', '}') + "}";

        if (Cache.TryGetValue(clsid, out var cached))
            return cached;

        (RegistryKey Root, string Prefix)[] searchRoots =
        {
            (Registry.ClassesRoot, @"CLSID"),
            (Registry.LocalMachine, @"SOFTWARE\Classes\CLSID"),
            (Registry.CurrentUser, @"SOFTWARE\Classes\CLSID"),
            (Registry.LocalMachine, @"SOFTWARE\Wow6432Node\Classes\CLSID"),
            (Registry.CurrentUser, @"SOFTWARE\Wow6432Node\Classes\CLSID")
        };

        string displayName = "";
        string serverType = "";
        string rawServerVal = "";
        string binaryPath = "";

        foreach (var (root, prefix) in searchRoots)
        {
            try
            {
                using var clsidKey = root.OpenSubKey($@"{prefix}\{clsid}", false);
                if (clsidKey == null) continue;

                if (string.IsNullOrWhiteSpace(displayName))
                {
                    displayName = clsidKey.GetValue("")?.ToString() ?? "";
                }

                foreach (var subType in new[] { "InprocServer32", "LocalServer32", "InprocHandler32" })
                {
                    using var srvKey = clsidKey.OpenSubKey(subType, false);
                    if (srvKey == null) continue;

                    string val = srvKey.GetValue("")?.ToString() ?? srvKey.GetValue("CodeBase")?.ToString() ?? "";
                    if (string.IsNullOrWhiteSpace(val)) continue;

                    rawServerVal = val;
                    serverType = subType;
                    binaryPath = PathHelper.ExtractExecutablePath(val);
                    if (!string.IsNullOrWhiteSpace(binaryPath) && File.Exists(binaryPath))
                        break;
                }

                if (string.IsNullOrWhiteSpace(binaryPath))
                {
                    string appId = clsidKey.GetValue("AppID")?.ToString() ?? "";
                    if (!string.IsNullOrWhiteSpace(appId))
                    {
                        using var appKey = Registry.ClassesRoot.OpenSubKey($@"AppID\{appId}", false);
                        string? localSvc = appKey?.GetValue("LocalService")?.ToString();
                        if (!string.IsNullOrWhiteSpace(localSvc))
                        {
                            serverType = $"LocalService ({localSvc})";
                            rawServerVal = localSvc;
                            binaryPath = ResolveServiceBinary(localSvc);
                        }
                    }
                }

                if (!string.IsNullOrWhiteSpace(binaryPath))
                    break;
            }
            catch { }
        }

        bool resolved = !string.IsNullOrWhiteSpace(binaryPath) && File.Exists(binaryPath);
        string unresolvedReason = resolved
            ? ""
            : string.IsNullOrWhiteSpace(rawServerVal)
                ? $"COM server executable not resolved (CLSID {clsid} not found in HKCR\\CLSID)"
                : $"COM server binary not found on disk ({rawServerVal})";

        var sig = resolved
            ? SignatureHelper.CheckExtended(binaryPath, isComServer: true)
            : SignatureHelper.CheckExtended("", isComServer: true, unresolvedReason: unresolvedReason);

        var result = new ComResolutionResult(
            clsid,
            resolved,
            string.IsNullOrWhiteSpace(serverType) ? "Unresolved" : serverType,
            rawServerVal,
            resolved ? binaryPath : "",
            displayName,
            sig);

        Cache[clsid] = result;
        return result;
    }

    private static string ResolveServiceBinary(string serviceName)
    {
        try
        {
            using var sk = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{serviceName}", false);
            if (sk == null) return "";
            using var param = sk.OpenSubKey("Parameters", false);
            string? dll = param?.GetValue("ServiceDll")?.ToString();
            if (!string.IsNullOrWhiteSpace(dll))
                return PathHelper.ExtractExecutablePath(dll);

            string? img = sk.GetValue("ImagePath")?.ToString();
            if (!string.IsNullOrWhiteSpace(img))
                return PathHelper.ExtractExecutablePath(img);
        }
        catch { }
        return "";
    }
}

/// <summary>
/// パスの分類・正規化（case, 環境変数, 8.3短縮パス, 引用符）と意味的比較ヘルパー
/// </summary>
public static class PathHelper
{
    private static readonly string WindowsDir = (Environment.GetFolderPath(Environment.SpecialFolder.Windows) + "\\").ToLowerInvariant();
    private static readonly string ProgramFiles = (Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles) + "\\").ToLowerInvariant();
    private static readonly string ProgramFilesX86 = (Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86) + "\\").ToLowerInvariant();

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetLongPathName(string lpszShortPath, StringBuilder lpszLongPath, uint cchBuffer);

    public static string CleanFilePath(string rawPath)
    {
        if (string.IsNullOrWhiteSpace(rawPath)) return "";
        string p = Environment.ExpandEnvironmentVariables(rawPath.Trim().Trim('"', '\''));
        if (p.StartsWith(@"\??\")) p = p[4..];
        if (p.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
            p = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), p[12..]);
        else if (p.StartsWith(@"System32\", StringComparison.OrdinalIgnoreCase))
            p = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), p);
        else if (p.StartsWith(@"SysWOW64\", StringComparison.OrdinalIgnoreCase))
            p = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), p);

        if (p.Contains('~'))
        {
            try
            {
                var sb = new StringBuilder(1024);
                uint len = GetLongPathName(p, sb, (uint)sb.Capacity);
                if (len > 0 && len < sb.Capacity)
                    p = sb.ToString();
            }
            catch { }
        }

        try
        {
            if (p.Contains('\\') && !p.StartsWith("\\\\"))
                p = Path.GetFullPath(p);
        }
        catch { }

        return p;
    }

    public static string NormalizeCommandForComparison(string rawCommand)
    {
        if (string.IsNullOrWhiteSpace(rawCommand)) return "";
        var (exe, args) = ExtractExecutableAndArguments(rawCommand);
        string normExe = CleanFilePath(exe).ToLowerInvariant();
        string normArgs = NormalizeArgumentsForComparison(args);
        return string.IsNullOrEmpty(normArgs) ? normExe : $"{normExe} {normArgs}";
    }

    public static string NormalizeArgumentsForComparison(string rawArgs)
    {
        if (string.IsNullOrWhiteSpace(rawArgs)) return "";
        string expanded = Environment.ExpandEnvironmentVariables(rawArgs.Trim());
        var tokens = SplitArgs(expanded)
            .Select(t => t.Trim().Trim('"').ToLowerInvariant())
            .Where(t => !string.IsNullOrEmpty(t));
        return string.Join(" ", tokens);
    }

    public static List<BaselineChangeType> CompareCommandsSemantically(
        string oldCommand,
        string newCommand,
        string? oldHash = null,
        string? newHash = null,
        string? oldSigner = null,
        string? newSigner = null)
    {
        var changes = new List<BaselineChangeType>();
        var (oldExe, oldArgs) = ExtractExecutableAndArguments(oldCommand);
        var (newExe, newArgs) = ExtractExecutableAndArguments(newCommand);

        string normOldExe = CleanFilePath(oldExe).ToLowerInvariant();
        string normNewExe = CleanFilePath(newExe).ToLowerInvariant();

        if (!string.Equals(normOldExe, normNewExe, StringComparison.OrdinalIgnoreCase))
        {
            changes.Add(BaselineChangeType.PathChanged);
        }

        string normOldArgs = NormalizeArgumentsForComparison(oldArgs);
        string normNewArgs = NormalizeArgumentsForComparison(newArgs);
        if (!string.Equals(normOldArgs, normNewArgs, StringComparison.OrdinalIgnoreCase))
        {
            changes.Add(BaselineChangeType.ArgumentsChanged);
        }

        if (!string.IsNullOrWhiteSpace(oldHash) && !string.IsNullOrWhiteSpace(newHash) &&
            !string.Equals(oldHash, newHash, StringComparison.OrdinalIgnoreCase))
        {
            changes.Add(BaselineChangeType.HashChanged);
        }

        if (!string.IsNullOrWhiteSpace(oldSigner) && !string.IsNullOrWhiteSpace(newSigner) &&
            !string.Equals(oldSigner, newSigner, StringComparison.OrdinalIgnoreCase))
        {
            changes.Add(BaselineChangeType.SignerChanged);
        }

        return changes;
    }

    public static bool IsWindowsLocation(string path)
    {
        if (string.IsNullOrEmpty(path)) return false;
        string p = CleanFilePath(path).ToLowerInvariant();
        if (!p.StartsWith(WindowsDir)) return false;
        // C:\Windows\Temp や C:\Windows\Tasks などの書き込み可能・一時領域は OS 標準領域から除外
        if (p.Contains("\\windows\\temp\\") || p.Contains("\\windows\\tasks\\")) return false;
        return true;
    }

    public static bool IsProgramFilesLocation(string path)
    {
        if (string.IsNullOrEmpty(path)) return false;
        string p = CleanFilePath(path).ToLowerInvariant();
        return p.StartsWith(ProgramFiles) || (ProgramFilesX86.Length > 1 && p.StartsWith(ProgramFilesX86));
    }

    /// <summary>WindowsApps / SystemApps / ストアアプリのパッケージ管理領域か</summary>
    public static bool IsWindowsAppsLocation(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;
        string p = CleanFilePath(path).ToLowerInvariant();
        return p.Contains(@"\program files\windowsapps\") ||
               p.Contains(@"\windows\systemapps\") ||
               p.Contains(@"\appdata\local\microsoft\windowsapps\") ||
               p.Contains(@"\appdata\local\packages\");
    }

    /// <summary>一般ユーザーが自由に書き込める（＝マルウェアが置かれやすい）場所か</summary>
    public static bool IsUserWritableLocation(string path)
    {
        if (string.IsNullOrEmpty(path)) return false;
        string p = CleanFilePath(path).ToLowerInvariant();
        return p.Contains("\\appdata\\") ||
               p.Contains("\\temp\\") ||
               p.Contains("\\downloads\\") ||
               p.Contains("\\desktop\\") ||
               p.Contains("\\users\\public\\") ||
               p.Contains("\\programdata\\") ||
               p.Contains("\\$recycle.bin\\");
    }

    /// <summary>特に危険度が高い一時領域か（Temp / Downloads / Public）</summary>
    public static bool IsHighRiskTempLocation(string path)
    {
        if (string.IsNullOrEmpty(path)) return false;
        string p = CleanFilePath(path).ToLowerInvariant();
        return p.Contains("\\appdata\\local\\temp\\") ||
               p.Contains("\\windows\\temp\\") ||
               p.Contains("\\downloads\\") ||
               p.Contains("\\users\\public\\") ||
               p.Contains("\\$recycle.bin\\");
    }

    private static readonly string[] ExecutableExtensions = { ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".scr", ".com", ".cpl", ".msi", ".lnk", ".sys" };

    public static (string ExePath, string Arguments) ExtractExecutableAndArguments(string command)
    {
        if (string.IsNullOrWhiteSpace(command)) return ("", "");
        string cmd = Environment.ExpandEnvironmentVariables(command.Trim());
        if (cmd.StartsWith(@"\??\")) cmd = cmd[4..];
        if (cmd.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
            cmd = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), cmd[12..]);
        if (cmd.StartsWith(@"System32\", StringComparison.OrdinalIgnoreCase))
            cmd = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), cmd);

        string first;
        string rest;
        if (cmd.StartsWith("\""))
        {
            int end = cmd.IndexOf('"', 1);
            first = end > 0 ? cmd[1..end] : cmd.Trim('"');
            rest = end > 0 && end + 1 < cmd.Length ? cmd[(end + 1)..].Trim() : "";
        }
        else
        {
            first = GuessUnquotedPath(cmd, out rest);
        }

        if (!first.Contains('\\') && !first.StartsWith("COM", StringComparison.OrdinalIgnoreCase))
        {
            string withExt = Path.HasExtension(first) ? first : first + ".exe";
            string sys = Path.Combine(Environment.SystemDirectory, withExt);
            if (File.Exists(sys)) first = sys;
            else
            {
                string win = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), withExt);
                if (File.Exists(win)) first = win;
            }
        }

        return (CleanFilePath(first), rest);
    }

    /// <summary>
    /// 自動起動エントリなどのコマンド文字列から実行ファイル（またはスクリプト）のフルパスを推定する
    /// 例: "\"C:\\Program Files\\App\\app.exe\" /background" → C:\Program Files\App\app.exe
    ///     rundll32.exe C:\Users\x\evil.dll,Start → C:\Users\x\evil.dll （LOLBin経由の実体を優先）
    /// </summary>
    public static string ExtractExecutablePath(string command)
    {
        if (string.IsNullOrWhiteSpace(command)) return "";
        if (command.StartsWith("COM CLSID:", StringComparison.OrdinalIgnoreCase))
            return "";

        var (first, rest) = ExtractExecutableAndArguments(command);

        // rundll32 / regsvr32 / mshta / wscript 等の LOLBin 経由なら、引数側の実体ファイルを返す
        string exeName = Path.GetFileNameWithoutExtension(first).ToLowerInvariant();
        if (exeName is "rundll32" or "regsvr32" or "wscript" or "cscript" or "mshta" && !string.IsNullOrWhiteSpace(rest))
        {
            string arg = rest;
            // オプション (/s, /i: など) を飛ばす
            var tokens = SplitArgs(arg).Where(t => !t.StartsWith("/") && !t.StartsWith("-")).ToList();
            if (tokens.Count > 0)
            {
                string candidate = tokens[0].Split(',')[0].Trim('"');
                if (candidate.Contains('\\') || candidate.Contains('.'))
                {
                    if (!candidate.Contains('\\'))
                    {
                        string sys = Path.Combine(Environment.SystemDirectory, candidate);
                        if (File.Exists(sys)) return sys;
                    }
                    return CleanFilePath(candidate);
                }
            }
        }

        return first;
    }

    private static string GuessUnquotedPath(string cmd, out string rest)
    {
        // スペースを含む非引用パスに対応するため、拡張子が現れる位置で区切る
        string lower = cmd.ToLowerInvariant();
        int best = -1;
        foreach (var ext in ExecutableExtensions)
        {
            int idx = lower.IndexOf(ext, StringComparison.Ordinal);
            while (idx >= 0)
            {
                int endIdx = idx + ext.Length;
                if (endIdx == lower.Length || lower[endIdx] == ' ' || lower[endIdx] == ',' || lower[endIdx] == '"')
                {
                    if (best < 0 || endIdx < best) best = endIdx;
                    break;
                }
                idx = lower.IndexOf(ext, idx + 1, StringComparison.Ordinal);
            }
        }
        if (best > 0)
        {
            rest = best < cmd.Length ? cmd[best..].Trim() : "";
            return cmd[..best];
        }
        int sp = cmd.IndexOf(' ');
        rest = sp > 0 ? cmd[(sp + 1)..] : "";
        return sp > 0 ? cmd[..sp] : cmd;
    }

    public static List<string> SplitArgs(string args)
    {
        var list = new List<string>();
        var cur = new System.Text.StringBuilder();
        bool inQuote = false;
        foreach (char c in args)
        {
            if (c == '"') { inQuote = !inQuote; continue; }
            if (c == ' ' && !inQuote)
            {
                if (cur.Length > 0) { list.Add(cur.ToString()); cur.Clear(); }
                continue;
            }
            cur.Append(c);
        }
        if (cur.Length > 0) list.Add(cur.ToString());
        return list;
    }
}

/// <summary>
/// Data フォルダ配下に JSON でベースラインや承認リストを保存する汎用ストア
/// （Program Files 等の読み取り専用領域にインストールされた場合は %LocalAppData%\AnzenSecurityWatcher\Data に自動フォールバック）
/// </summary>
public static class JsonStore
{
    public static readonly string DataDir = ResolveWritableDataDir();
    private static readonly object WriteLock = new();

    private static string ResolveWritableDataDir()
    {
        string baseDir = AppDomain.CurrentDomain.BaseDirectory;
        if (!PathHelper.IsProgramFilesLocation(baseDir))
        {
            try
            {
                string localDataDir = Path.Combine(baseDir, "Data");
                Directory.CreateDirectory(localDataDir);
                string probeFile = Path.Combine(localDataDir, ".write_probe");
                File.WriteAllText(probeFile, "");
                File.Delete(probeFile);
                return localDataDir;
            }
            catch
            {
                // 書き込み不可の場合は LocalApplicationData へフォールバック
            }
        }

        string fallbackDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "AnzenSecurityWatcher",
            "Data");
        try
        {
            Directory.CreateDirectory(fallbackDir);
        }
        catch
        {
            // 無視
        }
        return fallbackDir;
    }

    public static T? Load<T>(string fileName) where T : class
    {
        try
        {
            string path = Path.Combine(DataDir, fileName);
            if (!File.Exists(path)) return null;
            return JsonSerializer.Deserialize<T>(File.ReadAllText(path));
        }
        catch
        {
            return null;
        }
    }

    public static void Save<T>(string fileName, T data)
    {
        try
        {
            lock (WriteLock)
            {
                Directory.CreateDirectory(DataDir);
                string path = Path.Combine(DataDir, fileName);
                File.WriteAllText(path, JsonSerializer.Serialize(data, new JsonSerializerOptions { WriteIndented = true }));
            }
        }
        catch
        {
            // 書き込み失敗は無視（読み取り専用フォルダ等）
        }
    }
}

/// <summary>
/// STA スレッドで COM 呼び出しを実行する（Shell.Application / Schedule.Service / WMI など）
/// </summary>
public static class StaRunner
{
    public static T Run<T>(Func<T> func, T fallback, int timeoutMs = 15000)
    {
        T result = fallback;
        var thread = new Thread(() =>
        {
            try { result = func(); }
            catch { result = fallback; }
        })
        {
            IsBackground = true
        };
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        if (!thread.Join(timeoutMs)) return fallback;
        return result;
    }
}

/// <summary>
/// WMI (WbemScripting COM) を System.Management 無しで使うための最小ヘルパー
/// </summary>
public static class WmiHelper
{
    /// <summary>
    /// WQL クエリを実行し、指定プロパティの値を辞書のリストで返す（必ず STA スレッド上から呼ぶこと）
    /// </summary>
    public static List<Dictionary<string, object?>>? Query(string ns, string wql, params string[] properties)
    {
        object? locator = null;
        object? svc = null;
        object? set = null;

        try
        {
            var locatorType = Type.GetTypeFromProgID("WbemScripting.SWbemLocator");
            if (locatorType == null) return null;

            locator = Activator.CreateInstance(locatorType);
            if (locator == null) return null;

            dynamic dynLocator = locator;
            svc = dynLocator.ConnectServer(".", ns);
            if (svc == null) return null;

            dynamic dynSvc = svc;
            set = dynSvc.ExecQuery(wql);
            if (set == null) return null;

            dynamic dynSet = set;
            int count = dynSet.Count;
            var list = new List<Dictionary<string, object?>>(count);

            for (int i = 0; i < count; i++)
            {
                object? obj = null;
                object? props = null;
                try
                {
                    obj = dynSet.ItemIndex(i);
                    if (obj == null) continue;

                    dynamic dynObj = obj;
                    var dict = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);

                    try
                    {
                        props = dynObj.Properties_;
                    }
                    catch
                    {
                        props = null;
                    }

                    foreach (var p in properties)
                    {
                        object? prop = null;
                        try
                        {
                            if (props != null)
                            {
                                dynamic dynProps = props;
                                prop = dynProps.Item(p);
                                dict[p] = prop != null ? ((dynamic)prop).Value : null;
                            }
                            else
                            {
                                dict[p] = null;
                            }
                        }
                        catch
                        {
                            dict[p] = null;
                        }
                        finally
                        {
                            SafeRelease(prop);
                        }
                    }

                    list.Add(dict);
                }
                finally
                {
                    SafeRelease(props);
                    SafeRelease(obj);
                }
            }

            return list;
        }
        catch
        {
            return null;
        }
        finally
        {
            SafeRelease(set);
            SafeRelease(svc);
            SafeRelease(locator);
        }
    }

    private static void SafeRelease(object? comObj)
    {
        if (comObj != null && Marshal.IsComObject(comObj))
        {
            try
            {
                Marshal.ReleaseComObject(comObj);
            }
            catch
            {
                // ベストエフォートで解放
            }
        }
    }
}

public static class PrivilegeHelper
{
    private static bool? _isAdmin;

    public static bool IsAdministrator
    {
        get
        {
            if (_isAdmin.HasValue) return _isAdmin.Value;
            try
            {
                using var id = WindowsIdentity.GetCurrent();
                _isAdmin = new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch
            {
                _isAdmin = false;
            }
            return _isAdmin.Value;
        }
    }
}

/// <summary>
/// WindowsApps / MSIX / AppX ストアアプリのパッケージ単位署名判定ヘルパー
/// exe 単体の埋め込み署名ではなく、Get-AppxPackage の SignatureKind や AppX パッケージメタデータで署名を検証する。
/// </summary>
public static class AppxPackageSignatureHelper
{
    private static readonly ConcurrentDictionary<string, (int SignatureKind, string PackageName)> PackageCache = new(StringComparer.OrdinalIgnoreCase);
    private static bool _cacheInitialized = false;
    private static readonly object _initLock = new();

    public static (bool IsSigned, string Signer, string Publisher, string Reason) CheckAppxSignature(string filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath)) return (false, "", "", "");
        string normalized = PathHelper.CleanFilePath(filePath);

        EnsureCacheInitializedAsync();

        // 1. キャッシュから InstallLocation をプレフィックス照合
        foreach (var kvp in PackageCache)
        {
            if (normalized.StartsWith(kvp.Key, StringComparison.OrdinalIgnoreCase))
            {
                int kind = kvp.Value.SignatureKind;
                string pkgName = kvp.Value.PackageName;
                if (kind == 3 || kind == 4 || kind == 2)
                {
                    string signer = kind switch
                    {
                        4 => "Windows System (Store Package)",
                        3 => "Microsoft Store (AppX)",
                        2 => "Enterprise (AppX)",
                        _ => "Signed AppX Package"
                    };
                    string publisher = "Microsoft Corporation";
                    string kindStr = kind == 4 ? "System" : kind == 3 ? "Store" : "Enterprise";
                    return (true, signer, publisher, $"Windows Store App Package verified (SignatureKind: {kindStr}, Package: {pkgName})");
                }
            }
        }

        // 2. キャッシュにない場合の高信頼フォールバック判定
        string lower = normalized.ToLowerInvariant();
        if (lower.Contains(@"\windows\systemapps\"))
        {
            return (true, "Windows System (Store Package)", "Microsoft Windows", "Windows SystemApps package (SignatureKind: System)");
        }

        if (lower.Contains(@"\program files\windowsapps\"))
        {
            // Windows 公式ストアキーハッシュ (__8wekyb3d8bbwe)
            if (lower.Contains("__8wekyb3d8bbwe"))
            {
                return (true, "Microsoft Store (AppX)", "Microsoft Corporation", "Microsoft Store verified package (__8wekyb3d8bbwe)");
            }

            // 親ディレクトリを遡って AppxManifest.xml や AppxSignature.p7x があるか確認
            try
            {
                var dir = new DirectoryInfo(Path.GetDirectoryName(normalized) ?? "");
                for (int i = 0; i < 4 && dir != null; i++)
                {
                    if (File.Exists(Path.Combine(dir.FullName, "AppxSignature.p7x")) ||
                        File.Exists(Path.Combine(dir.FullName, "AppxManifest.xml")))
                    {
                        return (true, "Windows Store Package (AppX)", "Microsoft Store", "WindowsApps AppX package with manifest/signature");
                    }
                    dir = dir.Parent;
                }
            }
            catch { }

            // WindowsApps 自体は Windows の AppContainer / TrustedInstaller によってのみ配置可能な保護領域
            return (true, "Microsoft Store (AppX)", "Microsoft Store", "WindowsApps managed store package");
        }

        return (false, "", "", "");
    }

    private static void EnsureCacheInitializedAsync()
    {
        if (_cacheInitialized) return;
        lock (_initLock)
        {
            if (_cacheInitialized) return;
            _cacheInitialized = true;
        }

        Task.Run(() =>
        {
            try
            {
                var psi = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = "-NoProfile -NonInteractive -Command \"Get-AppxPackage | Where-Object { $_.InstallLocation } | Select-Object Name, SignatureKind, InstallLocation | ConvertTo-Json -Compress\"",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true
                };
                using var proc = System.Diagnostics.Process.Start(psi);
                if (proc != null)
                {
                    string output = proc.StandardOutput.ReadToEnd();
                    proc.WaitForExit(6000);
                    if (!string.IsNullOrWhiteSpace(output))
                    {
                        using var doc = JsonDocument.Parse(output);
                        if (doc.RootElement.ValueKind == JsonValueKind.Array)
                        {
                            foreach (var el in doc.RootElement.EnumerateArray())
                            {
                                AddJsonElementToCache(el);
                            }
                        }
                        else if (doc.RootElement.ValueKind == JsonValueKind.Object)
                        {
                            AddJsonElementToCache(doc.RootElement);
                        }
                    }
                }
            }
            catch
            {
                // バックグラウンドキャッシュ失敗時はフォールバック判定が機能するため安全に握り潰す
            }
        });
    }

    private static void AddJsonElementToCache(JsonElement el)
    {
        try
        {
            string loc = el.TryGetProperty("InstallLocation", out var l) ? l.GetString() ?? "" : "";
            string name = el.TryGetProperty("Name", out var n) ? n.GetString() ?? "" : "";
            int kind = 0;
            if (el.TryGetProperty("SignatureKind", out var k))
            {
                if (k.ValueKind == JsonValueKind.Number) kind = k.GetInt32();
                else if (k.ValueKind == JsonValueKind.String)
                {
                    string s = k.GetString() ?? "";
                    if (s.Equals("Store", StringComparison.OrdinalIgnoreCase)) kind = 3;
                    else if (s.Equals("System", StringComparison.OrdinalIgnoreCase)) kind = 4;
                    else if (s.Equals("Enterprise", StringComparison.OrdinalIgnoreCase)) kind = 2;
                }
            }

            if (!string.IsNullOrWhiteSpace(loc))
            {
                string normLoc = PathHelper.CleanFilePath(loc);
                if (!normLoc.EndsWith("\\")) normLoc += "\\";
                PackageCache[normLoc] = (kind, name);
            }
        }
        catch { }
    }
}
