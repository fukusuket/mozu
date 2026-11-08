# 攻撃に悪用されるフォルダ

調査日 2026-11-07。同日、別途のファクトチェック(リポジトリ外)を受けて改訂。目的: 侵害報告と検知ルールに名前が挙がる Windows のフォルダを洗い出し、mozu が現状そこで何を表現できるかを確認し、ルール見直し(P4-9)、P4-15、権限によるグループ分けの検討(product.md §6)に向けた測定候補を示す。HTML 版: [abused-folders.ja.html](abused-folders.ja.html)。続く計画項目: P4-24(候補の測定)、P2-18(`file_change`)、P4-P の候補(Public の 2 ルールの統合)。英語版: [abused-folders.md](abused-folders.md)。

## 入力

| 出典 | バージョン | 用途 |
|---|---|---|
| ATT&CK Enterprise(`mitre/cti`) | `50be388e93`(2026-10-13) | 言及数: 手順の説明文にフォルダ名が出てくる `uses` 関係 |
| SigmaHQ `rules`、`rules-threat-hunting`、`rules-emerging-threats`(`windows/` のみ) | `46da2482c`(2026-10-20) | 否定されていない selection でフォルダ名を使うルール。静的に読み込めるルール |
| [UltimateAppLockerByPassList](https://github.com/api0cradle/UltimateAppLockerByPassList/blob/master/Generic-AppLockerbypasses.md) | `master`(2026-11-07 参照) | `C:\Windows` 配下で一般ユーザーが書き込めると報告されているフォルダ |
| mozu の `detect`(`crates/detect/src/lib.rs`)、自前ルール、`folder` 分類 | `main` `acbedc2` | mozu が現在 Sigma に出しているもの([architecture.md § Folder](../architecture.md#folder)) |
| ATT&CK [T1074.001](https://attack.mitre.org/techniques/T1074/001/) | v20 | ステージングの例(APT5 の `C:\Users\Public`、Leviathan の `C:\Windows\Debug` と `C:\PerfLogs`) |

以下の件数はすべて [abused-folders-counts.csv](abused-folders-counts.csv) の行の集合として確認できる(列は `source,folder,id,name,category,level,loadable,technique`。`source` は `attack`、`sigma`、`sigma-loadable` のいずれか)。

### 手法

| 手順 | 決まり |
|---|---|
| フォルダの照合 | フォルダごとに小文字化した正規表現を 1 つ使う(例: `\\users\\public\\` または `%public%`)。ATT&CK の文章では末尾の `\` を省略可とし、「Recycle Bin」にも一致させる |
| Sigma の正の文字列 | `condition` で `not` の後に**だけ**現れる selection を除いた、すべての selection の文字列(`not x`、`not 1 of x*`、`not all of x*`、`not (a or b)`)。両方で使われる selection は正として数える |
| Sigma で読み込めるか(静的) | `logsource.category` が `file_event`、`file_delete`、`file_rename`、`create_stream_hash` のいずれかで、否定側も含むすべての selection のフィールドが mozu の出すもの(`TargetFilename`、`SourceFilename`、`CreationUtcTime`、`UtcTime`)だけであること |
| ATT&CK | 技術への `uses` 関係。revoked と deprecated の関係・技術は除外 |

限界: condition の解析は上記の形だけを扱い、任意の入れ子は扱わない。相関ルールの文書は `detection` がないため除外される。「読み込める」は静的な判定で、mozu のローダーを通したものではない。`rules/` で読み込める 88 ルールは [detection-gaps.md](detection-gaps.md) で desktop6 に対してローダーが数えた件数と同じだが、ルール単位で突き合わせてはいない。スクリプトはリポジトリの外にある。コミットするかは別の計画項目で判断する。

## mozu が現在出しているもの

| 事実 | 元 | ここで効く制約 |
|---|---|---|
| `file_event`(`TargetFilename`、`CreationUtcTime`、`FnCreationUtcTime`、`SiCreatedBeforeFnCreated`) | 使用中のすべての `$MFT` ファイル | 存在するファイルであって、作成ではない |
| `file_event` / `file_rename` / `file_delete`(`TargetFilename`、`SourceFilename`、`UtcTime`) | USN のクローズレコード | `UtcTime` を持つのは USN 由来のイベントだけ |
| `create_stream_hash` | 名前付きの `$DATA` ストリーム | — |
| `service: baseline_outside` | ベースラインの照合 | ベースラインが必要 |
| **ディレクトリ** | — | **出していない**: `file_target` はディレクトリに `None` を返し(`crates/detect/src/lib.rs:82`)、USN のディレクトリのレコードも飛ばす(`:105`)。ルールからディレクトリが見えるのは、その配下のファイルのパスを通してだけ |

## 結論

1. ATT&CK の手順の説明文で最も多く名前が挙がるフォルダ(ユーザーの Temp 50、`AppData\Roaming` 31、`ntds.dit` のコピー 25、ProgramData 22、`Users\Public` 19、`Windows\Temp` 17)は、すでに mozu の `folder` 分類があるか、パスのルールで届く。言及数は実際の攻撃頻度ではない。
2. 候補の多くは現在のファイルの事実で書ける。そのまま書けないものが 2 つある: フォルダ自体の名前が怪しいもの(F6)は、配下のファイルか新しいディレクトリの事実が要る。「存在する」ではなく「作成された」を言うには、USN の行だけが満たす条件が要る(F2)。
3. イベントログを消されても残りうる永続化・改ざんの痕跡で、自前ルールがないものが 3 つある: Startup フォルダ(T1547.001)、`System32\Tasks` 配下のタスクファイル(T1053.005)、ベースラインにないドライバ。パスだけでは、タスクの動作、ショートカットのリンク先、ドライバの脆弱性、実行の有無は分からない。
4. パスからは誰が書き込めるかは分からない: 公開リストでは `C:\Windows` 配下に一般ユーザーが書き込めるフォルダが 16 ある。権限によるグループ分けには DACL が要るが、P4-11 は owner SID だけが対象なので mozu では確認できない。P4-15 でグループ分けを削除する方針を支持する。
5. SigmaHQ のフォルダ系ルールはほとんどが `process_creation`(`Image`)向け: `Users\Public` の 103 ルール中 57、`Windows\Temp` の 93 ルール中 54。静的に読み込めるのはフォルダごとに 0〜12 ルール。
6. 現時点で新しいルールは提案しない。F1〜F7 は測定候補で、レベルは測定後に ADR 0016 に従って決める。

## フォルダ一覧

書き込み = Microsoft の資料または上記の公開リストが報告する既定の書き込み権限で、測定値ではない。ATT&CK = そのフォルダ名が出てくる手順の説明文(説明文の数 / グループ・ソフトウェア・キャンペーンの数)。Sigma = 否定されていない selection でそのフォルダ名を使うルール数 / うち静的に読み込める数。複数フォルダをまとめた行は、ルールと出典を重複なしで数えた。

| フォルダ | 書き込み | 悪用(ATT&CK の説明文またはルールの説明より) | ATT&CK | Sigma | mozu `folder` | 自前ルール |
|---|---|---|---|---|---|---|
| `Users\<u>\AppData\Local\Temp` | ユーザー | 投下、ステージング(T1074.001 ×16)、偽装 | 50 / 38 | 87 / 12 | `temp` | `executable_in_temp`(low)、削除(low) |
| `Users\<u>\AppData\Roaming` | ユーザー | Run キーのペイロード(T1547.001 ×6)、ステージング | 31 / 26 | 47 / 4 | `appdata` | — |
| `Users\<u>\AppData\Local`(その他) | ユーザー | サイドローディング、ブラウザのデータ | 7 / 7 | 49 / 7 | `appdata` | — |
| `ProgramData`(直下と新しいサブフォルダ) | 全ユーザーが作成可 | ステージング、永続化、隠しファイル(T1564.001)、偽装 | 22 / 18 | 33 / 2 | `programdata` | —(ProgramData 直下のルールは P1 で見送り) |
| `Users\Public` | 全ユーザー | ステージング(T1074.001 ×6)、ツール、タスクのペイロード | 19 / 16 | 103 / 3 | `public` | `public_executable`、`public_script_or_archive`(medium) |
| `Windows\Temp` | 全ユーザーが作成可 | ステージング、`ntds.dit` やハイブのコピー、後始末 | 17 / 14 | 93 / 6 | `temp` | `executable_in_temp`(low)、削除(low) |
| `PerfLogs` | 未確認 | ステージング(Leviathan、Wizard Spider) | 2 / 2 | 63 / 2 | `other` | — |
| `$Recycle.Bin` | ユーザー(自分の SID のフォルダ) | ステージング(GALLIUM、menuPass、BackdoorDiplomacy)。USB 上の偽の `RECYCLE.BIN`(Mustang Panda)。残り 3 件の言及は消去や探索 | 7 / 7 | 8 / 0 | `other` | — |
| Startup(`…\Start Menu\Programs\Startup`、ユーザー別と ProgramData) | ユーザー / 管理者 | T1547.001、T1547.009 | 3 / 3 | 17 / 1 | `appdata` / `programdata` | — |
| `Windows\System32\Tasks`、`Windows\Tasks` | 管理者 / 全ユーザー(`Windows\Tasks`) | T1053.005 のタスクファイル、投下先 | 0 / 0 | 23 / 2 | `windows` | — |
| `Windows\System32\drivers`、その他の場所の `.sys` | 管理者 | ドライバ、偽装 | 1 / 1 | 2 / 0 | `windows` | —(ベースライン外バイナリのルールは `.sys` を見ない) |
| 一般ユーザーが書ける `C:\Windows` 配下(`Tracing`、`Registration\CRMLog`、`spool\drivers\color`、`MachineKeys` など) | 全ユーザー(リストによる) | `C:\Windows` を信頼する許可リストを回避して投下・実行 | 0 / 0 | 各 3〜5 / 0〜1 | `windows` | `outside_baseline_windows_binary`(high、`.exe`/`.dll`) |
| めったに書き込まれない `C:\Windows` 配下(`Fonts`、`IME`、`Help`、`addins`、`debug`) | 管理者 | `debug` でのステージング(Leviathan)、偽装 | 1 / 1 | 3〜8 / 0 | `windows` | 同上 |
| 偽フォルダ(`C:\Windows \`、`C:\Program Files \`) | 管理者 | UAC バイパス、DLL 検索順序(T1574) | 0 / 0 | 3 / 1 | `other` | — |
| `C:\` 直下(`C:\Intel`、`C:\temp`、`C:\program.exe`) | 全ユーザーがフォルダを作成可 | ツール置き場、引用符なしサービスパス(T1574.009) | 0 / 0 | 8 / 2 | `other` | — |
| `Users\<u>\Downloads`、`Desktop` | ユーザー | 初期侵入、身代金要求文 | 3 + 2 / 5 | 31 + 39 / 0 | `downloads`、`desktop` | `double_extension`(medium) |
| `inetpub\wwwroot`、Exchange の `aspnet_client`/`FrontEnd` | 管理者 / サービス | Web シェル(T1505.003) | 2 / 1 | 11 / 1 | `other` | — |
| `NTDS`、`System32\config` のコピー | 管理者 | 認証情報の窃取(T1003.003 ×16) | 27 / 20 | 16 / 3 | コピー先のフォルダ | — |
| `winevt\Logs`、`Prefetch` | 管理者 | 痕跡の削除(T1070) | 2 / 2 | 2 / 1 | `windows` | `event_log_deleted`(high)、`prefetch_deleted`(medium) |
| `SYSVOL`、`NETLOGON`(DC) | ドメイン管理者 | GPO による展開(T1484.001) | 0 / 0 | 5 / 0 | `windows` / `other` | —(Server は MVP 外) |

スケジュールタスクや Startup の悪用はよくあるが、手順の説明文がフォルダ名まで書くことは少ないので、ここでの件数の少なさにはあまり意味がない。

### `C:\Windows` 配下で一般ユーザーが書き込めるフォルダ(公開リスト、未測定)

`Tasks`、`Temp`、`tracing`、`Registration\CRMLog`、`System32\FxsTmp`、`System32\com\dmp`、`System32\Microsoft\Crypto\RSA\MachineKeys`、`System32\spool\PRINTERS`、`System32\spool\SERVERS`、`System32\spool\drivers\color`、`System32\Tasks\Microsoft\Windows\SyncCenter`、`System32\Tasks_Migrated`、`SysWOW64\FxsTmp`、`SysWOW64\com\dmp`、`SysWOW64\Tasks\Microsoft\Windows\SyncCenter`、`SysWOW64\Tasks\Microsoft\Windows\PLA\System`。

mozu には DACL の事実がないため、このリストを確認できない。判断がこれに依存する場合は、ベースライン VM 上で手作業で確認する(`icacls`)。

## 候補

判定基準は [detection-gaps.md § Gate](detection-gaps.md#gate-for-a-new-rule) と同じ(G1 頻度、G2 既存ルールで未検知、G3 正常な管理作業と区別できる、G4 サンプルを用意できる、G5 適切なレイヤー)。どの候補にもレベルは付けない。測定結果から ADR 0016 に従って決める。

| ID | 候補 | 現在の事実 | 一致して分かること / 分からないこと | 測定すべき正常なケース | 状態 |
|---|---|---|---|---|---|
| F1 | Startup フォルダにあるベースライン外の実行ファイル・スクリプト・`.lnk` | `TargetFilename`、`baseline_outside` | そこにファイルがある / リンク先や実行の有無は分からない。読み込める SigmaHQ のルールは `.exe` と `.lnk` を含まない | ベンダーの `.lnk`(Teams、OneDrive、VPN クライアント) | **測定** |
| F2 | `Windows\System32\Tasks\` 配下にあるベースライン外のタスクファイル | `TargetFilename`、`baseline_outside`。`UtcTime` を持つのは USN の行だけ | タスクファイルがある(USN のみの条件を付ければ、作成された) / トリガー、動作、コマンドは分からない | 更新ツールのタスク(Google、Edge、Adobe、OneDrive) | **測定**。まず USN で作成された行だけをルールで選べることを回帰テストで示す。示せなければ「存在する」と書く |
| F3 | ベースライン外の `.sys`(ベースライン外ドライバの候補) | `TargetFilename`、`baseline_outside` | ベースラインにないドライバらしいファイル / 脆弱性、署名者、ロード、防御回避への利用は分からない。BYOVD の検知ではない | ハードウェア、AV、VPN、バックアップ製品のドライバ | **測定** |
| F4 | `C:\PerfLogs\` 配下の実行ファイル・スクリプト・アーカイブ | `TargetFilename` | そこにファイルがある | 不明。使用中のホストでの PerfLogs の中身 | SigmaHQ `file_event_win_perflogs_susp_files` を mozu のローダーと回帰サンプルで**測定** |
| F5 | `$Recycle.Bin\<SID>\` の直下にあり、名前が `$R`/`$I` で始まらず `desktop.ini` でもないファイル | `TargetFilename`(正規表現) | エクスプローラーが名付けていないファイルがある / 誰が書いたかは分からない | ごみ箱に入れたフォルダ配下のファイル(`$R…\<元の名前>`。「直下」の条件で除外)、アプリによる書き込み、Windows のバージョン差、移行 | **測定** |
| F6 | 名前が空白またはドットで終わるフォルダを含むパス | そのようなフォルダの配下の**ファイル**の `TargetFilename`(正規表現) | 通常の Win32 の名前処理では末尾の ASCII の空白・ドットは除去されるが、NTFS 上にはそのような名前を作れる / 空のフォルダは見えない(ディレクトリは出していない) | 不明 | **事実の制約**: ファイルの形で測定する。空のフォルダにはディレクトリの事実が要る(新しい計画項目) |
| F7 | `C:\ProgramData\` または `C:\` の直下の実行ファイル・スクリプト(サブフォルダ内のファイルは除く) | `TargetFilename`(正規表現、`executable_in_users_root` と同じ形) | その階層にファイルがある | 直下にファイルを置くインストーラーやエージェント | **測定** |
| F8 | 一般ユーザーが書ける `C:\Windows` 配下のスクリプト(`.ps1`、`.bat`、`.vbs` など) | `TargetFilename`、`baseline_outside` | — | — | **保留**: 既存ルールの拡張子の変更は H5。測定の後で |
| F9 | Temp/ProgramData/Public/PerfLogs で作成後に削除されたアーカイブや `.dmp` | `file_event` + `file_delete`、`temporal_ordered` | — | バックアップ、クラッシュダンプ | P4-8 まで**保留**。しきい値は正常なデータから決める |
| F10 | `system_binary_outside_system32` へのシステム名の追加(`rundll32`、`dllhost`、`conhost`、`taskhostw`、`spoolsv`、`explorer`) | `TargetFilename` | — | 各名前の正常な場所 | H5 の変更の前に**測定** |

候補ごとに手元の 12 台で記録する項目: 一致したファイル、親ディレクトリ、拡張子、`$MFT` 由来か USN 由来か、USN の操作。そのうえで回帰サンプル(G4)で確認する。

### 隣接するケースの SigmaHQ ルール(F11 を分割)

| ケース | SigmaHQ のルール | 静的な判定 | 状態 |
|---|---|---|---|
| `ntds.dit`、SAM、ハイブのコピー | `file_event_win_sam_dump`(high)、`file_event_win_ntds_exfil_tools`(high)、`file_event_win_hktl_hivenightmare_file_exports`(high)、`file_event_win_ntds_dit_creation`(low) | 読み込める | mozu のローダーとテストイベントではまだ確認していない |
| LSASS のダンプ | `file_event_win_lsass_default_dump_file_names`(high) | 読み込める | 同上 |
| 既定の GPO フォルダへの書き込み | `file_event_win_susp_default_gpo_dir_write`(medium) | 読み込める | 同上。Server は MVP 外 |
| Web シェル | `file_event_win_webshell_creation_detect` | 読み込めない(`Image`) | 現状は**未カバー**。自前ルールは「後で」(detection-gaps.md) |

範囲外(事実がない): ユーザー補助のバイナリの置き換え(`sethc.exe`)には、ベースラインのファイルに対するデータ上書きのカテゴリが要る。Defender の除外はレジストリにある。SigmaHQ の Office `XLSTART`/Word `STARTUP` のルールは、`office_addin_persistence` を除き `Image` が必要。

## 測定(P4-24、12 台)

2026-11-08 に `37942fa`(P2-18)の `mozu` と、リポジトリ外に置いた下書きルールで実行した(候補ごとに `informational` のルール 1 本。F1〜F3 は `service: baseline_outside` 版も、F2 は `file_event` の中では USN で作成された行だけを選ぶ `UtcTime|exists: true` 版も用意。後者が動くことはテスト `a_rule_can_select_usn_created_rows_with_utctime_exists` で確認)。再実行で出力はバイト単位で一致した。Atomic Red Team の手順(G4)は未実施。

| ホスト | OS(`$MFT` から推定) | ベースライン |
|---|---|---|
| Yamato CTF ×9(`ACC-*`、`IT-*`) | Windows 7 SP1、6.1.7601 | なし: VWR に Windows 7 がないため上限値 |
| Simulated-Case-1 ×3(desktop6、dc1、files5) | Server 2025 Standard、26100.1742 | VWR `WindowsServer2025_24H2_Standard_20241101_26100.1742`(ビルド一致) |

一致したファイル数(重複なし。パスは `<user>`、`<SID>` で伏せた):

| ID | Yamato ×9、ベースラインなし | dc1 / desktop6 / files5、ベースラインなし | dc1 / desktop6 / files5、ベースライン外 | 一致したもの |
|---|---|---|---|---|
| F1 Startup | 各 1。IT-03 は 3 | 1 / 2 / 0 | 1 / 2 / 0 | Yamato 全 9 台の ProgramData の Startup にある検証環境用の `.lnk`。`<user>` の Startup に作成された `.exe` と `.hta`(IT-03)。ユーザーの Startup の `.lnk`(dc1、desktop6)。ProgramData の Startup にあるリモートアクセスツールの `.lnk`(desktop6) |
| F2 タスク | 81〜83 | 221 / 195 / 222 | 33 / 8 / 34 | ベースライン外: VWR にない Windows 自身のタスク(dc1/files5 では 27 件がセットアップ中に削除)、Edge の更新タスク、少数の Microsoft 以外の名前(files5 で作成後に削除されたランダムな 8 文字のタスク、desktop6 のリモートアクセスツールの監視タスクと汎用的な名前 2 件) |
| F2 作成(USN のみ) | 1〜3 | 221 / 8 / 222 | — | Yamato: 再作成された Defender のタスクと、ACC-04 と IT-02 の短く不自然な名前。Server: セットアップがジャーナルの期間内にほとんどのタスクを作り直していた |
| F3 `.sys` | 648〜652 | 1,167 / 1,191 / 1,166 | 21 / 45 / 20 | ベースライン外: Defender のプラットフォームと定義の更新、一時フォルダ(`Windows\SystemTemp\<GUID>`、`WinSxS\Temp\InFlight`)、ルートの `pagefile.sys`、Sysmon(検証環境)、リモートアクセスツールのドライバ 26 件(desktop6)、メモリ取得用のドライバ(dc1) |
| F4 PerfLogs(SigmaHQ) | 0 | 0 / 0 / 0 | — | — |
| F5 `$Recycle.Bin` | 0 | 0 / 0 / 0 | — | — |
| F6 末尾の空白・ドット | 0 | 0 / 0 / 0 | — | — |
| F7 `C:\`/ProgramData の直下 | 各 2 | 1 / 0 / 0 | — | 検証環境の構築物のみ: `C:\` の `sysmon.exe` と `vcredist.exe`(Yamato)、`C:\` のユーザー作成用 `.ps1`(dc1) |
| F10 システム名 | 0 | 0 / 0 / 0 | — | — |

上記のファイルの元になった行の出どころ(ベースラインがある場合はベースライン外。USN の操作はクローズレコードの理由):

| ID | Yamato ×9 | dc1 | desktop6 | files5 |
|---|---|---|---|---|
| F1 | `$MFT` のみ。IT-03 は USN の `FILE_CREATE` も 2 件(`.exe`、`.hta`) | `$MFT` 1、USN `FILE_CREATE` 1(`.lnk`) | `$MFT` 2、USN `FILE_CREATE` 2(`.lnk`) | — |
| F2(ベースライン外) | — | `$MFT` 6、USN `FILE_CREATE` 33(うち 27 ファイルは後で削除)。拡張子なし | `$MFT` 8、USN `FILE_CREATE` 3。拡張子なし | `$MFT` 6、USN `FILE_CREATE` 34(うち 28 は後で削除)。拡張子なし |
| F2 作成(ベースラインなし) | ホストごとに USN `FILE_CREATE`(トランザクション)1〜7 | USN `FILE_CREATE` 232 | 12 | 233 |
| F3(ベースライン外) | — | `$MFT` 13、USN `FILE_CREATE` 16(うち 5 は `DATA_OVERWRITE` も、10 は `BASIC_INFO_CHANGE` も) | `$MFT` 40、USN `FILE_CREATE` 38(うち 31 は `DATA_OVERWRITE` も) | `$MFT` 14、USN `FILE_CREATE` 15 |
| F7 | `$MFT` のみ(`C:\` の `.exe` ×2) | USN `FILE_CREATE` 1(`C:\` の `.ps1`) | — | — |

判断(「保留」と「保持」は暫定。Atomic の手順で P4-24 を閉じるときに、各候補を「提案」か「見送り」に決める):

| ID | 判断 | 理由 |
|---|---|---|
| F1 | 後の H1 で**ルールを提案**(`baseline_outside` なし)。レベルはその場でこの件数から決める(ADR 0016) | 一致はすべて検証環境のツールか攻撃関連(ラベルは人が確認)。ベースライン版では Windows 7 のホストを取りこぼす |
| F2 | 自前のベースライン(P4-3、P4-4)まで**保留** | ベースライン外の一致の多くは VWR にない Windows のタスク。注目すべきは少数の不自然な名前。「作成された」が必要なら `UtcTime|exists` が使える |
| F3 | P4-4 まで**保留** | 更新、一時フォルダ、`pagefile.sys` が大半。ルールには P2-9d と同じ一時フォルダの除外も要る |
| F4、F5、F6、F10 | **Atomic の手順まで保持**、ルールはまだ作らない | 誤検知 0。ただし陽性のサンプル(G4)もない |
| F7 | Atomic の手順で事例が出ない限り**見送り** | 一致したのは構築時の残骸だけ |

## 既存機能への影響

| 機能 | 調査結果 | 提案 |
|---|---|---|
| `folder` 分類 | 最も多く名前が挙がるフォルダには分類がある。`PerfLogs`、`$Recycle.Bin`、`C:\` 直下、偽フォルダは `other`、Startup は `appdata`/`programdata` になる | 分類は追加しない。ルールはパスで照合でき、残りは検索で足りる |
| 権限によるグループ分け(product.md §6) | パス ≠ 権限。DACL はどの計画項目にも含まれない(P4-11 は owner SID のみ) | 予定どおり P4-15 で削除 |
| P4-15 ベースライン外のファイルをディレクトリ単位で表示 | `ProgramData`、`C:\`、`Program Files` に新しくできた最上位フォルダはツールの痕跡になる | 維持。`C:\` 直下のフォルダも一覧に含める |
| `outside_baseline_windows_binary` | `.sys` とスクリプトを見ていない | 測定後に F3/F8(H5) |
| `executable_in_temp` / 削除(low) | Temp は最も多く名前が挙がり、誤検知も多い | `low` のまま。F9 のような相関ルールで価値が出る |
| `double_extension`(medium) | SigmaHQ の `file_event_win_susp_double_extension`(high、静的に読み込める)と重複するが、SigmaHQ は同梱しない(Phase 2) | 維持 |
| `file_change` カテゴリ | USN の `BASIC_INFO_CHANGE` を Sigma の `file_change` として出している。自前ルールは使っておらず、SigmaHQ の `file_change` ルール 2 本は `Image` か `PreviousCreationUtcTime` が必要で読み込めない。Sigma の `file_change` は Sysmon EID 2(作成日時の変更)で、より狭い意味 | 出力をやめる(計画 P2-18) |
| `public_executable` + `public_script_or_archive` | 同じフォルダを拡張子で 2 ルールに分けている。SigmaHQ は 1 ルール | P4-P で統合候補(計画に記載) |

## Codex の調査との比較用

| 項目 | 本調査 |
|---|---|
| 一覧にしたフォルダ | 20 行。一般ユーザーが書ける `C:\Windows` 配下は 16(公開リスト) |
| ATT&CK の言及数(上位) | ユーザーの Temp 50、Roaming 31、NTDS/config のコピー 27、ProgramData 22、Public 19、`Windows\Temp` 17 |
| フォルダ名を使う Sigma ルール(上位) | `Users\Public` 103、`Windows\Temp` 93、ユーザーの Temp 87、`PerfLogs` 63 |
| 静的に読み込める SigmaHQ の Windows ルール | 93(`rules/` 88、`rules-threat-hunting/` 5) |
| 結論 | 新規ルール 0。測定候補 7(F1〜F7。F6 は事実の制約あり)。F8〜F10 は保留または先に測定 |

## 注意点

- ATT&CK と Sigma の件数は報告やルール作成の多さを表し、実際の攻撃頻度ではない。
- SigmaHQ の `file_event` ルールはプロセスによる作成を前提とする。mozu では `$MFT` のすべてのファイルが `file_event` になるため、読み込めるルールは古いファイルでも発火する(detection-gaps.md)。
- 手元の 12 台は測定済み(上記)。攻撃コーパス(Atomic Red Team)は未実施。Windows 7 のホストにはベースラインがない。
- 既定の ACL は Microsoft の資料と 1 つの公開リストによる。mozu では確認できない。
