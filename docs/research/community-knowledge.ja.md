# コミュニティナレッジ: ライセンスと効果見込み

調査日 2026-11-07。同日、改訂後の abused-folders.ja.md に合わせて F3 の記述を修正。目的: Sigma と ATT&CK 以外のコミュニティのデータセットについて、mozu がライセンスと既存の決定のもとで使えるか、使うと何が得られるかを示す。[abused-folders.ja.md](abused-folders.ja.md) の続き。英語版: [community-knowledge.md](community-knowledge.md)。

## 利用可否を決める制約

| 出典 | 決まり |
|---|---|
| [ADR 0001](../adr/0001-license.md) | コードは AGPL-3.0-only、ルールは DRL 1.1、依存は AGPL と互換であること |
| [ADR 0006](../adr/0006-gpl-reference-data.md) | GPL-3.0 のデータ(LOLBAS、HijackLibs、winbindex)は AGPL のコードと一緒にデータとして同梱し、実行時に照合して**事実**と `service: unexpected_location` にする。DRL ルールの中身には決して入れない |
| [ADR 0019](../adr/0019-generic-rules-only.md) | ルールに製品名やツール名を並べない。サードパーティのデータからルールを生成しない。ADR 0006 の「LOLDrivers は DRL ルールにしてよい」より優先する |
| 入力 | `$MFT`、`$J`、`$Boot`、`$SDS` のみ。分かるのは名前、パス、サイズ、時刻、ADS 名。**ハッシュ、署名、内容、プロセスの情報はない** |
| ネットワークなし | データは固定して同梱する。解析時に取得しない |

このため、データセットが mozu に入る道は次の 4 つ:

| 方法 | 意味 | 必要な判断 |
|---|---|---|
| **データ** | バイナリに同梱し、実行時に照合して事実・logsource にする。ルールは汎用のまま | データセットごとに H2(ADR 0006 の型)。`NOTICE` とライセンス文 |
| **開発用** | テストと測定にだけ使い、同梱しない | テストデータの決まりに従う。実行時の依存なし |
| **参照** | ルールや拡張子リスト、説明文の設計のために読む。何もコピーしない | なし |
| **不可** | ライセンス、内容、入手性のいずれかで使えない | — |

## データセットごとの判定

ライセンスは GitHub API(`license.spdx_id`。`NOASSERTION` の場合は `LICENSE` を読んだ)で 2026-11-07 に確認。件数は同日に公開フィードかリポジトリのツリーから数えた。

| 出典 | ライセンス | 最終更新 | 使い方 | 効果見込み |
|---|---|---|---|---|
| [HijackLibs](https://github.com/wietze/HijackLibs) | GPL-3.0 | 2026-10-28 | **データ**(ADR 0006 で決定済み) | **高** |
| [LOLDrivers](https://github.com/magicsword-io/LOLDrivers) | Apache-2.0 | 2026-11-02 | **データ**(事実として。ルールにはしない、ADR 0019) | **中〜高** |
| [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) | MIT | 2026-11-06 | **開発用**(G4 の回帰サンプル) | **高**(測定) |
| [Ransomware Tool Matrix](https://github.com/BushidoUK/Ransomware-Tool-Matrix) | CC-BY-4.0 | 2026-08-29 | **開発用**(評価セット) | **高**(測定) |
| [ThreatLabz ransomware_notes](https://github.com/ThreatLabz/ransomware_notes) | MIT | 2026-08-13 | **開発用**(P4-9 のしきい値) | **中〜高** |
| [LOLBAS](https://github.com/LOLBAS-Project/LOLBAS) | GPL-3.0 | 2026-09-26 | **データ**(ADR 0006) | 中 |
| [LOLRMM](https://github.com/magicsword-io/LOLRMM) | Apache-2.0 | 2026-11-05 | **データ**、詳細表示のみ(concept-review.md) | 中 |
| [KapeFiles](https://github.com/EricZimmerman/KapeFiles) | MIT | 2026-11-05 | 当面は**参照**。追加収集の一覧ができたらデータ | 中 |
| [ForensicArtifacts](https://github.com/ForensicArtifacts/artifacts) | Apache-2.0 | 2026-11-01 | **参照**(追加収集の一覧) | 低〜中 |
| [winbindex](https://github.com/m417z/winbindex) | GPL-3.0 | 2026-11-06 | **データ**にできる(ADR 0006)が保留 | 低 |
| NIST NSRL RDS | 米国政府の著作物。再配布条件は取得できず | 四半期ごと | 保留 | 不明(後述) |
| [persistence-info](https://github.com/persistence-info/persistence-info.github.io) | GPL-3.0 | 2023-12-19 | **参照** | 低 |
| [Splunk security_content](https://github.com/splunk/security_content) | Apache-2.0 | 2026-11-05 | **参照** | 低 |
| [Elastic detection-rules](https://github.com/elastic/detection-rules) | Elastic License 2.0 | 2026-11-06 | **参照のみ。何もコピーしない** | 低 |
| [WTFBins](https://github.com/mttaggart/wtfbins) | MIT | 2025-03-30 | 参照 | 低 |
| [LOLAPPS](https://github.com/LOLAPPS-Project/LOLAPPS) | GPL-3.0 | 2025-02-19 | 不可(更新停止。同じ型は LOLBAS で足りる) | 低 |
| Microsoft の脆弱ドライバ ブロックリスト | ダウンロードセンターの条件で、オープンライセンスなし | 四半期ごと | 不可(代わりに LOLDrivers) | — |
| [ransomware.live](https://github.com/JMousqueton/ransomware.live) | Unlicense | 2026-07-20 | 不可(被害者・リークサイトの情報で、ファイルの事実がない) | — |
| [The DFIR Report Sigma-Rules](https://github.com/The-DFIR-Report/Sigma-Rules) | GPL-3.0 | 2026-07-08 | 不可(`LICENSE` と `README.md` しかない) | — |
| filesec.io | — | — | 不可(2026-11-07 に名前解決できず、リポジトリも見つからない) | — |

ライセンスの互換性: GPL-3.0 は AGPL-3.0 と組み合わせられる(GPLv3 §13)。Apache-2.0、MIT、CC-BY-4.0 は (A)GPL-3.0 に一方向で互換で、`NOTICE` での帰属表示が要る。Elastic License 2.0 はオープンソースではなく利用制限が付くため、その文面やルールのロジックを AGPL のコードにも DRL ルールにもコピーしない。

## 詳細と効果見込み

### データの候補

| 出典 | 内容(2026-11-07) | NTFS メタデータで使える部分 | 追加される事実 | 効果と理由 | 限界 |
|---|---|---|---|---|---|
| HijackLibs | DLL 627 件。うち 597 件に本来の場所(428 件は System32/SysWOW64)。実行ファイルとの組は、サイドローディング 1,907、環境変数 459、ファントム 20、検索順序 17 | 名前とパス: すべて | `known hijackable DLL` かつ本来の場所の外 → `service: unexpected_location`。任意で「同じフォルダに脆弱な実行ファイルがある」 | **高**: DLL サイドローディングは署名済みの実行ファイルと DLL を ProgramData、AppData、Temp、Public に置く。`outside_baseline_windows_binary` は `C:\Windows` しか見ないので、ここを拾えない。汎用ルール(`unexpected_location` + `.dll`)ならルールに名前を並べずに済む | 627 件中 471 件は Microsoft の DLL。正規アプリが同名の DLL を同梱することがある → `baseline_outside` と組み合わせる。12 台で測定 |
| LOLDrivers | ドライバ 713 件(脆弱 588、悪性 125)。サンプル 2,430 件はハッシュのみ。ファイル名は `Tags` にあり、一意 647 件、うち 31 件はハッシュ風の名前(`driver_<hex>.sys`) | 名前のみ(mozu はハッシュを取れない) | `.sys` に対する `known vulnerable driver name` | **中〜高**: abused-folders.ja.md の F3(ベースライン外ドライバの候補)を、カタログにある名前に絞り込める。防御回避のためのドライバ悪用は暗号化の前に報告されている(Ransomware Tool Matrix の 225 ツール中、防御回避が 24) | 名前の一致は BYOVD の検知ではない: バージョン、署名者、ロード、利用は分からない。改名されたドライバは拾えない。修正済みでも同名なら一致する → 事実として出すだけで、それ単独では検知にしない |
| LOLBAS | 245 件、本来のパス 613(System32/SysWOW64 227、その他の `C:\Windows` 80、Program Files 282、その他 24) | 名前とパス: すべて | `known LOLBin` かつ本来のパスの外 | **中**: `system_binary_outside_system32` を 6 名から 245 名に一般化する。本来のパス以外にコピーされた LOLBin は偽装の兆候 | 実行は見えない。改名したコピーは拾えない。ADR 0006 で決定済み |
| LOLRMM | ツール 358 件。うち 318 件にインストールパス(パスなしの名前 846、Program Files 234、ProgramData 46、AppData 35、その他 186)。111 件にディスク上の痕跡 845 | 名前とパス | ベースライン外ディレクトリの詳細表示での `catalog match`(P4-15) | **中**: RMM はランサムウェアのツールで最大の分類(42 ツール)。専門家でない人が「AnyDesk のフォルダ」と気付ける | ADR 0019 で製品ルール 307 本は削除済み。データとして出すだけで、検知にはしない |
| winbindex | Microsoft 製バイナリのバージョンとパスの履歴 | 名前とパス | 既知のパス以外にある Microsoft 製バイナリ | **低**: ホストのビルドについては、ビルドごとのベースラインがすでに答えている | 大きい。ベースラインがないビルドを扱うとき(P4-5 の近いビルドへのフォールバック)にだけ役立つ |
| NSRL RDS | RDSv3 SQLite。非常に大きい(NIST 自身が注意喚起)。ファイルの行は名前、サイズ、ハッシュを持ち、パスはない | 名前 + サイズ(`$MFT` にサイズがある) | `known software file (name and size)` | 不明: ベースライン外ファイルのうち他社製ソフトによる誤検知を減らせる可能性がある(product.md P5)。ただし名前 + サイズの照合は弱く、データは巨大 | 条件を取得できず。まず P4-4 の正規化と比べる |

### 開発用と参照

| 出典 | 内容 | 効果と理由 |
|---|---|---|
| Atomic Red Team | 353 技術。Windows のテスト数: T1547.001 21、T1053.005 14、T1003.003 11、T1574.001 7、T1070.004 7、T1543.003 6、T1564.001 5、T1486 4、T1036.005 3、T1068 2、T1074.001 2、T1505.003 1 | 測定に**高**: abused-folders.ja.md の F1〜F7 と P4-9 の G4 回帰サンプル(メンテナーの VM で実行して収集し、収集物はリポジトリの外に置く) |
| Ransomware Tool Matrix | 8 分類 225 ツール(RMM 42、認証情報窃取 42、探索 36、攻撃ツール 28、持ち出し 28、防御回避 24、ネットワーク 15、LOLBAS 10)。10 以上の集団が使うツールは 13 | 測定に**高**: P4-19 のラベルセット(「10 以上の集団が使う 13 ツールの痕跡がレポートに出るか」)。ルールの中身には決して使わない(ADR 0019) |
| ThreatLabz ransomware_notes | 222 ファミリー、元の名前のままの要求文ファイル 335(`readme*` 35、`how*to*recover*` 12) | **中〜高**: P4-9 の汎用の相関ルール「同じ新しいファイル名が数分のうちに多くのディレクトリに作られる」のしきい値を、要求文の名前を並べずに調整できる |
| KapeFiles | ターゲット 427(Apps 194、Windows 102、複合 36、ブラウザ 31、アンチウイルス 29) | **中**: 検知ごとに次に収集すべき KAPE ターゲットを示せる(concept-review.md の追加収集の一覧)。M2 で KAPE の出力はすでに読める |
| ForensicArtifacts | 痕跡のパス定義(`windows.yaml`、`webservers.yaml` など)。`windows_dll_hijacking.yaml` は Windows 7 由来 | **低〜中**: 追加収集の一覧で KapeFiles と同じ役割。DLL の一覧は `C:\Windows` 配下ならベースラインのルールでカバー済み |
| persistence-info | 44 件、ほとんどがレジストリ。ファイルとして見えるのは Startup フォルダ、タスクスケジューラ、PowerShell プロファイル、ごみ箱、`wpbbin`、Windows Terminal のプロファイル | **低**: abused-folders.ja.md の F1/F2 と PowerShell プロファイルのルールを裏付ける。それ以外は NTFS から見えない |
| Splunk security_content | 2,204 検知(エンドポイント 1,529)、SPL | **低**: Sigma と同じくほとんどがプロセス前提。変換の手間もかかる |
| Elastic detection-rules | EQL/KQL | **低**。ライセンス上、読む以上の再利用はできない |
| WTFBins | 正常だが怪しく見えるバイナリ 48 件 | **低**: プロセスの振る舞いで、ファイルの事実ではない |

## 推奨

| 順 | 対応 | 理由 | 必要な判断 |
|---|---|---|---|
| 1 | HijackLibs を `unexpected_location` のデータにし、汎用ルール 1 本を追加 | 決定済み(ADR 0006)。ベースラインのルールが見ない場所で効果が最も大きい | 計画項目(H1)。データの取り込みは H2 |
| 2 | Atomic Red Team で F1〜F7 と P4-9 のサンプルを作る | G4 なしではルールを採用しない。安価 | 計画項目。VM の操作は人が行う |
| 3 | Ransomware Tool Matrix を P4-19 のラベルセットに使う | 主な利用者の状況で、製品の主張(攻撃関連ファイルの 80 % 以上を表示)を測れる | P4-19 の ADR に含める |
| 4 | LOLDrivers の名前を、F3 の候補の横に事実として出す(F3 の測定後) | 一覧にあるドライバ名を他の第三者製ドライバと区別できる。Apache-2.0 | 新しい ADR(GPL 以外のデータで、ADR 0019 との境界) |
| 5 | ThreatLabz の要求文で P4-9 のしきい値を決める | 汎用の相関ルールを測って決められる | P4-9 の中で |
| 6 | LOLBAS と LOLRMM を事実として出す | 詳細表示で役立つ。検知にはしない | P4-13 の後 |
| — | KapeFiles / ForensicArtifacts を追加収集の一覧に使う | その一覧が計画項目になった場合のみ | まずプロダクトとしてのニーズ |
| — | NSRL、winbindex | P4-4/P4-5 の数値で誤検知が残ると分かるまで保留 | まず測定 |

## 注意点

- ライセンスは各リポジトリの申告による。データセットには別条件のサードパーティの内容が含まれることがある。取り込み時に確認し直す(ADR 0006 の手順)。
- 「効果」は件数と適合度からの判断で、測定値ではない。データとして使う項目はどれも、ルールのレベルを決める前に手元の 12 台でホストごとの件数を測る(ADR 0016)。
- 名前だけの照合は改名で回避できる。カタログとの一致はすべて検知の横に出す事実で、並び順には決して使わない(AGENTS.md)。
- フィードは件数を数えるために一度だけ(GET のみ)スクラッチ用のディレクトリにダウンロードした。コミットはしていない。
