<div align="center">

# 🛡️ Anzen Security Watcher（安全セキュリティ・ウォッチャー）

**「見えない通信」「0.2秒の瞬間ターミナル」「密かな画面流出」を、すべて可視化する。**

*C# / .NET 8 WPF ネイティブ設計による、Windows 11 向け超軽量リアルタイム・セキュリティ監視 ＆ AI SOC 診断支援ツール*

[![Language: English](https://img.shields.io/badge/Language-English-0078D4?style=for-the-badge)](./README.md)
[![Language: 日本語](https://img.shields.io/badge/言語-日本語-DC143C?style=for-the-badge)](./README.ja.md)
[![Language: 简体中文](https://img.shields.io/badge/语言-简体中文-DE2910?style=for-the-badge)](./README.zh-CN.md)
[![Language: Español](https://img.shields.io/badge/Idioma-Español-FFC400?style=for-the-badge)](./README.es.md)

[![Platform](https://img.shields.io/badge/Platform-Windows%2011-0078D6?style=flat-square&logo=windows11)](https://www.microsoft.com/windows)
[![Runtime](https://img.shields.io/badge/.NET-8.0%20WPF-512BD4?style=flat-square&logo=dotnet)](https://dotnet.microsoft.com/)
[![Architecture](https://img.shields.io/badge/Engine-Win32%20%26%20NT%20Native%20API-00A4EF?style=flat-square)](#主な機能5大コアエンジン)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)](./LICENSE)

</div>

---

## 🌍 言語選択 / Choose Your Language

- 🇺🇸 **[English (Default)](./README.md)**
- 🇯🇵 **[日本語 (Japanese)](./README.ja.md)** — 現在表示中
- 🇨🇳 **[简体中文 (Simplified Chinese)](./README.zh-CN.md)**
- 🇪🇸 **[Español (Spanish)](./README.es.md)**

---

## 💡 概要：なぜ「Anzen Security Watcher」なのか？

PCを使っていて、「**黒い画面（コマンドプロンプトやPowerShell）が 0.2秒 だけパッと出て消えたけれど、今の何！？**」と不安になったことはありませんか？  
あるいは、「**今この瞬間、自分のPCがどこの国と通信しているのか」「いつの間にかリモート操作ツールで画面を覗き見られていないか**」気になったことはありませんか？

従来のウイルス対策ソフトは「ブラックボックス」であり、アラートが鳴るまでPC内部で何が起きているのか人間には見えません。一方で、大企業向けのEDR製品は高額かつ重厚すぎて、個人や現場のエンジニアが手軽に使えるものではありませんでした。

**Anzen Security Watcher** は、20年間ミッションクリティカルなシステム開発に携わってきたエンジニアが個人プロジェクトとして設計・開発した、**「すべての人に、プロ水準のセキュリティ可視化とAI診断を届ける」**オープンソース・ツールです。  
Win32 / NT ネイティブ API による超高速・低負荷な監視と、ChatGPT / Claude / Gemini にワンクリックで相談できる「AIプロンプト自動生成（個人情報マスク付）」を融合させました。

---

## 🎯 読者・利用者別のメリット

| 対象読者 | Anzen Security Watcher が提供する価値 |
| :--- | :--- |
| 🧑‍💻 **一般のPCユーザー・テレワーカー** | カメラ・マイクの盗聴や、意図しない「画面共有・遠隔操作」を最前面ポップアップで即座に警告。PCの安全度を**100点満点**（グレードA〜E）で一目で把握し、不安な挙動はボタン1つでAIに質問できます。 |
| 🛡️ **情シス・セキュリティ担当者 (Blue Team)** | カーネルドライバ不要で**50ミリ秒（0.05秒）の瞬間ターミナル捕捉**、難読化PowerShell（`-enc`）の自動復号、周期的ビーコン通信の統計検知、DLLサイドローディング検知を即座に実行できます。 |
| 🏢 **組織・チーム管理者・テレワーカー** | 在宅ワーク端末や業務PCでの「意図しない画面共有・リモート操作」「バックグラウンドの不審通信」を即座に可視化し、情報漏洩や不正アクセスのリスクを早期発見できます。 |
| ⚙️ **開発者・セキュリティ研究者** | C# / .NET 8 WPF による Win32 IP Helper API、`NtQueryInformationProcess`、WTSセッション監視、変動係数（$CV = \sigma / \mu$）を用いた周期性検知の実装リファレンスとして活用できます。 |

---

## ✨ 主な機能（5大コアエンジン）

### 1. 🌐 TCP / UDP 国別通信リアルタイムモニター
- **プロセス直結の通信可視化**: Win32 IP Helper API (`GetExtendedTcpTable` / `GetExtendedUdpTable`) を駆使し、現在PCが行っているすべての TCP 通信および UDP エンドポイントと所有プロセス（PID・プロセス名・実行ファイルパス）をリアルタイムに紐付けます。
- **ハイブリッド GeoIP エンジン**: ローカル/LAN判定および主要クラウド・地域CIDRのオフライン即時判定に加え、APIキー不要のGeoIPサービス (`ipwho.is` / `ip-api.com`) を非同期照会して永続キャッシュ (`Data/geoip_cache.json`) に保存します。
- **ワンクリック国別フィルタリング**: 画面上部の**国別サマリーカード**をクリックするだけで、特定の国との通信だけを瞬時に絞り込み表示できます。
- **不審通信の自動ハイライト**: `powershell`, `cmd`, `rundll32`, `mshta` 等の LOLBins（環境寄生型バイナリ）による外部通信や、高リスクポート（`3389`, `5900`, `4444` 等）・重点警戒国との通信を自動ハイライトします。

### 2. 🖥️ リモート画面共有・RDP リアルタイム検知＆最前面アラート
- **Windows RDP 複合検知**: WTS API (`WTSEnumerateSessions` / `WTSQuerySessionInformation`)、`GetSystemMetrics(SM_REMOTESESSION)`、`rdpclip.exe` の稼働、および TCP/UDP `3389`番ポートの通信を複合監視します。
- **遠隔操作ソフトの「待機中」と「画面流出中 (ACTIVE)」の厳密識別**: AnyDesk, TeamViewer, UltraVNC / TightVNC / RealVNC, RustDesk, Chrome Remote Desktop, Windows クイックアシスト, Parsec, Splashtop, ScreenConnect, LogMeIn 等を監視し、単なる「バックグラウンド常駐」か「**実際に外部とセッション確立して画面が流れている状態 (ACTIVE)**」かを正確に識別します。
- **Web会議の画面共有検知**: Zoomの画面キャプチャ専用プロセス (`CptHost.exe`) や画面共有緑枠クラス (`ZPFTEWndClass` / `ZPFloatToolbarClass`)、Microsoft Teams・Discord・Slack・Webブラウザの画面共有インジケータを Win32 `EnumWindows` でリアルタイム捕捉します。
- **見逃さない警告アクション**: 画面共有・遠隔接続を検知した瞬間、メイン画面上部のバナーが赤色警告に切り替わり、**画面右下に最前面（Topmost）警告ポップアップ**および**Windowsタスクトレイ通知**を即座に表示します。

### 3. ⚡ プロセス・コマンドライン監視（0.05秒の瞬間ターミナル捕捉 ＆ 周期的出現 ＆ 難読化解析）
- **⚡ 瞬間ターミナル / 短命プロセス・スナイパー監視（50ms 高速捕捉）**: Win32 `CreateToolhelp32Snapshot` を用いた **0.05秒（50ms）周期**の超軽量スナイパー監視により、画面に0.1〜0.3秒だけ「ふっと現れてすぐ消える」ターミナルや短命プロセスを逃さず捕捉します。消滅前に**完全なコマンドライン引数**・**親プロセス（`svchost/Schedule` や `WmiPrvSE` 等）**・**生存時間（ミリ秒）**・**同時刻に動いたスケジュールタスク名**を記録します。
- **⏰ 直近実行スケジュールタスク照合**: 「⏰ 直近実行タスク調査」ボタンひとつで、Windows タスクスケジューラ内の全フォルダ（`\Microsoft\Windows` 配下含む）から直近60分以内に自動実行されたタスクを抽出し、瞬間ターミナルの正体を特定します。
- **周期的出現プロセス（C2ビーコン・定期タスク検知）**: プロセスの起動タイムスタンプ履歴を追跡し、起動間隔の平均値 ($\mu$) と標準偏差 ($\sigma$)・変動係数 ($CV = \sigma / \mu$) を算出して、一定の周期で繰り返し現れるプロセスを自動リストアップします。
- **初出・レア・未署名プロセス抽出**: 初回起動時のベースライン (`Data/process_baseline.json`) と比較し、新規出現プロセスや `Temp` / `Downloads` / `AppData` 等からデジタル署名なしで実行されているプログラムをあぶり出します。
- **コマンドライン引数取得＆自動復号**: NT API (`NtQueryInformationProcess`) で引数を完全取得し、PowerShell の Base64 難読化 (`-enc` の自動復号対応)・`IEX`・`DownloadString`・シャドウコピー削除 (`vssadmin delete shadows`)・Office文書からのシェル起動等をリアルタイム検知します。

### 4. 🛡️ システム防御・安全スコア（10項目自動採点 ＆ 永続化・プライバシー総合監視）
- **📊 セキュリティ設定の100点満点診断（グレード A〜E）**: Microsoft Defender リアルタイム保護、Windows ファイアウォール、UAC、SmartScreen、RDP着信/NLA、UEFI セキュアブート、SMBv1 無効化、自動再生ブロック、`hosts` ファイル改ざん有無、プロキシ設定の 10 項目を自動採点し、ワンクリックで設定画面を開けます。
- **🚀 自動起動（永続化）エントリ監視**: `Run` / `RunOnce` レジストリ、スタートアップフォルダ、`Winlogon` (`Shell` / `Userinit`)、`IFEO` (`Debugger`)、自動起動サービス、タスクスケジューラを横断スキャンし、ベースラインとの差分で改ざんを検知します。
- **🧩 DLL サイドローディング検知**: デジタル署名付きの正規 EXE と同じフォルダに未署名の不審な DLL が配置されている状態を検出します。
- **📷 カメラ・マイク使用中アプリの特定**: `CapabilityAccessManager\ConsentStore` レジストリから、現在カメラやマイクを使用中のアプリ (`LastUsedTimeStop == 0`) と直近履歴を特定します。
- **🎹 キーロガー兆候 ＆ 📋 クリップボード監視**: グローバルキーフック (`SetWindowsHookEx` / `GetAsyncKeyState`) のインポート兆候や、バックグラウンドでクリップボードを監視・保持するプロセスを検出します。
- **🔌 BadUSB・📜 ルート証明書追加・🔐 アカウント改ざん監視**: 監視開始後のUSB/HIDキーボード接続、信頼されたルート証明機関ストアへの不正証明書追加（MITM対策）、イベントID `4625`（ログオン失敗）/ `4720`（アカウント作成）、`Administrators` グループの変更を監視します。

### 5. 🤖 AIに相談すべきログ（プライバシー保護マスク ＆ ワンクリック・プロンプト生成）
- **SOCアナリスト水準の診断プロンプト生成**: 検知した要注意イベントやPC全体のスナップショットを構造化し、ChatGPT / Claude / Gemini 等にそのまま貼り付けて専門的な診断を受けられるプロンプトを自動生成します。
- **自動プライバシー保護マスク**: 外部AIへ貼り付ける際、PC名 (`[MY_PC]`)、Windowsユーザー名 (`[USER_NAME]`)、プライベートIP (`192.168.x.x` 等) を自動的に伏せ字（マスク）に変換するため、情報漏洩の心配がありません。

### 6. 🔋 省電力・バッテリー駆動への配慮（スキャン間隔の切替）
- **スキャン間隔の柔軟な設定**: ノートPCでのバッテリー消費を抑えるため、設定画面から「高速: 3秒」「標準: 5秒」「省電力: 15秒」をワンクリックで切り替え可能です。
- **詳細スキャンの自動連動**: タスクスケジューラCOM探索、全サービス列挙、レジストリ探索等の重い詳細スキャンもスキャン間隔に比例して連動（18秒 / 30秒 / 90秒）し、瞬間ターミナル捕捉スナイパーのウェイトも自動調整されるため、バッテリー駆動時でも安心して常駐監視できます。

---

## 🚀 インストール・起動方法

### 動作環境
- **対応OS**: Windows 11（64bit推奨 / Windows 10 でも動作可能）
- **ランタイム**: [.NET 8.0 デスクトップ ランタイム](https://dotnet.microsoft.com/ja-jp/download/dotnet/8.0)（※MSIインストーラー版およびバイナリ実行時に必要。ソースからビルドする場合は [.NET 8 SDK](https://dotnet.microsoft.com/ja-jp/download/dotnet/8.0)）
- **推奨権限**: 通常ユーザーでも動作しますが、セキュリティイベントログ（`4625`/`4720`）の取得や全プロセスのコマンドライン解析を行うため**「管理者として実行」**を推奨します。

---

### 📦 一般ユーザー向け：MSI インストーラーによる導入（推奨・最も簡単）
開発環境（.NET SDK や Git 等）がセットアップされていない一般的な環境では、ビルド済みインストーラーのご利用を推奨します。

1. **[Releases](../../releases)** ページから最新の **`AnzenSecurityWatcher-Setup-*-x64.msi`** をダウンロードします。
2. ダウンロードした MSI ファイルを実行し、画面の指示に従ってインストールします。
   - デスクトップおよびスタートメニューにショートカットが自動作成されます。
   - インストール後は、ショートカットを右クリックして**「管理者として実行」**で起動してください。

---

### 🛠️ 開発者向け：ソースコードからのビルド・起動手順
ソースコードの検証や独自カスタマイズを行いたい開発者・エンジニア向けの手順です。（※ [.NET 8 SDK](https://dotnet.microsoft.com/ja-jp/download/dotnet/8.0) が必要です）

#### 1. リポジトリのクローン
```powershell
git clone https://github.com/sdozono/Anzen-Security-Watcher.git
cd anzen-security-watcher
```

#### 2. アプリケーションの起動（2つの方法）
- **方法A: バッチファイルからワンクリック起動**  
  プロジェクトルートの **`run-watcher.bat`** をダブルクリックします。  
  *(※初回実行時は自動的に `dotnet run --configuration Release` によるビルドと起動が行われます。ビルド完了後の2回目以降は、生成されたバイナリ `bin\Release\net8.0-windows\AnzenSecurityWatcher.exe` が即座に高速起動します)*

- **方法B: .NET CLI からの手動ビルド＆起動**  
  ```powershell
  dotnet build --configuration Release
  dotnet run --configuration Release
  ```

#### （参考）MSI インストーラーのローカルビルド
WiX Toolset v5 を用いて自前で MSI パッケージを生成する場合は、付属のビルドスクリプトを実行します：
```powershell
powershell -ExecutionPolicy Bypass -File .\build-installer.ps1
```
*(※ `installer\output\AnzenSecurityWatcher-Setup-*-x64.msi` が出力されます)*

---

## 🎙️ 開発者メッセージ（Developer's Message）

> *「20年間、ミッションクリティカルなシステム開発に携わってきた中で、一般のPCユーザーや現場のエンジニアが『自分のPCで今何が起きているのか』を直感的に把握できる手段の必要性を強く感じていました。*  
> *従来のセキュリティ製品はブラックボックスになりがちで、不審な挙動に気づくことが困難です。本ツールは個人が日々の安心のために使えるオープンソースとして公開していますが、**エンタープライズでの本格利用、企業における数千台規模のPCの一括管理、社内閉域網・プライベートAI連携などにこちらのアイデアやアーキテクチャを活用したいと思われる場合は、どうぞお気軽にお問い合わせ・ご相談ください。**」*

---

## 🤝 コントリビューション・お問い合わせ（Contributing & Inquiries）

本プロジェクトはオープンソース（MIT License）の個人プロジェクトです。個人のご利用はもちろん、企業での活用相談や改善提案も歓迎しています。

- 💬 **エンタープライズ利用・アイデア活用のご相談**: 企業での大規模展開や一括管理などへのアイデア活用に関するご相談は、[GitHub Discussions](../../discussions) または [GitHub Issues](../../issues) よりお気軽にご連絡ください。
- 🐛 **バグ報告・機能リクエスト**: [GitHub Issues](../../issues) までお気軽に投稿してください。
- 🛠️ **Pull Request**: 新機能の追加やバグ修正の PR を歓迎します。

---

## 📄 ライセンス（License）

本ソフトウェアは **[MIT License](./LICENSE)** のもとで公開されています。商用・非商用を問わず自由にご利用いただけます。

---

<div align="center">
  <sub>Crafted with ❤️ and 20 years of engineering craftsmanship as an open-source personal project.</sub>
</div>
