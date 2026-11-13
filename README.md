# Sokuho Result

陸上競技の速報記録を共有するWebアプリです。ローカル開発はNode.js 24以降で動作し、公開版はCloudflare PagesとSupabase Freeを使用します。

## 起動

```sh
node server.js
```

ローカルで管理者画面を使う場合は、起動前に開発用アカウントを設定します。管理者登録画面は公開していません。

```sh
bash setup-admin.sh
```

画面の案内に従ってメールアドレスと12文字以上のパスワードを入力すると、管理者アカウントを初期化してサーバーを起動します。パスワードは入力中に表示されません。

ブラウザで `http://localhost:4173` を開きます。ログイン画面は `/login` からも登録・ログイン不要で開けます。運営者はログインまたはアカウント登録後、大会ページを作成します。大会ごとに `/r/<ID>` 形式の固定URLが発行されます。

## 利用者の種類

- 閲覧者: 登録・ログイン不要です。大会運営者から受け取った速報URLを開いて閲覧します。記録操作はできません。
- 運営者: メールアドレスと12文字以上のパスワードで登録します。自分が作成した大会の編集・スタート・フィニッシュ記録を操作できます。
- 管理者: ローカルでは `ADMIN_EMAIL` と `ADMIN_PASSWORD` で起動時に作成され、公開版ではGitHub Actions Secretsの `SOKUHO_ADMIN_EMAIL` と `SOKUHO_ADMIN_PASSWORD` で初回APIアクセス時に作成されます。公開版でSecretのパスワードを変更すると、次回デプロイ後のAPIアクセス時に既存管理者のパスワードを更新し、その管理者の既存セッションを無効化します。管理者タブから登録運営者と大会の一覧を確認・削除できます。運営者アカウントを削除すると、その運営者の主催大会・記録とログインセッションを削除し、他大会の共同運営グループからも解除します。管理者アカウントはこの画面から削除できません。一般登録から管理者にはなれません。

運営者ページから管理者へ問い合わせ・パスワード変更依頼を送信でき、返信はアプリ内で確認できます。管理者は本人確認後、運営者一覧またはパスワード変更依頼から一時パスワードを発行できます。一時パスワードは発行時のみ画面に表示され、既存セッションを無効にします。本人へ安全な別経路で伝えてください。運営者はログイン後に新しいパスワードを設定するまで他の機能を使えません。管理者は運営者全員へのアップデート告知を作成でき、運営者ページに掲載されます。これらの問い合わせ・告知機能はメールを送信せず、ログイン中のアプリ内で利用します。

ローカル版のアカウント、セッション、お問い合わせ、告知は `data/accounts.json` に保存されます。公開版ではアカウント・大会・セッション・お問い合わせ・告知をSupabaseに保存し、パスワードはソルト付きハッシュで管理します。ログインセッションはブラウザーのlocalStorageに保存されます。SupabaseのService Role Keyや管理者パスワードをソース管理へ登録しないでください。

## 大会ごとの共同運営

大会主催者は大会ページで共同運営グループを作成し、登録済み運営者のメールアドレスを指定して招待できます。共同運営者は運営者ページの「担当する大会」一覧から大会を開き、競技・スタート・フィニッシュを操作できます。グループの作成・メンバー招待・解除は主催者のみ可能です。解除後はその大会を操作できなくなります。

大会一覧と管理者一覧には、主催者・共同運営者と各アカウントの担当大会数を表示します。主要な一覧と操作画面はスマートフォン幅に対応しています。

## 速報の記録

1. 運営者としてログインし、大会ページの「競技を追加」から競技名、組、選手名を登録します。
2. スタート地点の端末で「スタートを記録」を押します。
3. フィニッシュ地点の端末で、通過した選手の「FINISH」を押します。
4. 記録と着順は共有ページに最大15秒程度で反映されます。

ローカル大会データは `data/races.json`、公開版データはSupabaseに保存されます。共有URLは閲覧専用で、記録を編集できるのは大会を作成した運営者だけです。

## 公開について

このリポジトリはCloudflare PagesのGit連携で自動公開し、Supabase FreeをAPI・DBとして使用します。公開URLは `https://<Cloudflare Pagesのプロジェクト名>.pages.dev/` で、GitHubのユーザー名はURLに入りません。大会の共有URLはそこに `r/<ID>` を付けたものです。閲覧者にアカウントは不要です。

### 初回設定（画面を見ながら順番に進める）

Cloudflare Pagesの静的ファイル配信は無料です。Supabase FreeでもAPIリクエスト数は無制限ですが、Edge Functionは月50万回、DBは500MB、通信量などの無料枠上限があります。Supabase Freeは低利用状態が7日続くと一時停止される場合があり、これを無効にする設定はありません。この構成ではGitHub ActionsからSupabaseのDBを毎日確認して低利用状態になりにくくしますが、Supabaseの一時停止を無効化・保証するものではありません。最新条件は[Supabase料金表](https://supabase.com/pricing)と[Cloudflare Pages料金](https://pages.cloudflare.com/)で確認してください。

1. **Cloudflare Pagesプロジェクトを作る**
   - [Cloudflare Dashboard](https://dash.cloudflare.com/sign-up)で無料アカウントを作成／ログインします。Workers Paidへの変更は不要です。
   - **Workers & Pages → Create application → Pages → Connect to Git** を選び、GitHubを接続してこのリポジトリを選びます。
   - Project nameは `sokuho-result` などユーザー名を含まない文字列にします。使用済みなら末尾に数字を追加します。Framework presetは **None**、Build commandは `node build-pages.mjs`、Build output directoryは `public` にして作成します。公開URLは `https://<project-name>.pages.dev/` になり、GitHubのユーザー名は含まれません。
   - Pagesプロジェクトの **Settings → Environment variables → Production** に `SUPABASE_ANON_KEY` を追加します。値はSupabaseの公開用 anon / publishable keyです。
   - 作成直後の初回ビルドが環境変数未設定で失敗した場合は、変数を保存した後に **Deployments → Retry deployment** を押します。
2. **既存Supabaseプロジェクトの接続情報を確認**
   - すでに作成した [Supabaseプロジェクト](https://supabase.com/dashboard/project/cfaowiuefyrmpksavenh)を使います。課金プランの変更は不要です。Project IDは `cfaowiuefyrmpksavenh` です。
   - Supabaseの **Project Settings → API** から公開用 `anon` / `publishable` keyと `service_role` keyを確認します。公開用keyはCloudflare Pagesへ、`service_role` keyはGitHub Secretへ登録します。`service_role` keyは漏らさないでください。秘密のkeyはチャットへ送らないでください。
   - Supabase画面上部の **Connect → Session pooler** を選び、接続文字列をコピーします。GitHub ActionsのネットワークからIPv4でDBに接続するため、**Direct connectionではなくSession pooler**を使います。文字列内の `[YOUR-PASSWORD]` はDatabase passwordに置き換えます。パスワードに `@` や `#` などが含まれる場合はURLエンコードが必要です。
   - Supabaseアカウントの **Access Tokens** からGitHub Actions用のAccess Tokenを作成します。
3. **GitHub Actionsに値を登録**
   - このリポジトリの **Settings → Secrets and variables → Actions** を開きます。
   - **Variables**に `CLOUDFLARE_PAGES_PROJECT` を追加します。値は手順1で設定したProject nameです。
   - **Secrets**に次の5項目を追加します。
     - `SUPABASE_ACCESS_TOKEN` — 手順2のSupabase Access Token
     - `SUPABASE_DB_URL` — 上記のSession pooler接続文字列（パスワードを含むためSecretに保存）
     - `SUPABASE_SERVICE_ROLE_KEY` — Supabaseの `service_role` key
     - `SOKUHO_ADMIN_EMAIL` — 速報アプリの管理者メールアドレス
     - `SOKUHO_ADMIN_PASSWORD` — 管理者パスワード（12文字以上）
   - 値を入力したら **Add variable** / **Add secret** を押します。秘密の値はチャットへ送らないでください。
4. **変更をGitHubへ送信**
   - VS Code左側の **ソース管理**を開き、変更をコミットして `main` へ **Push / Sync Changes** します。この作業環境から私が直接pushするにはGitHubログインが必要ですが、ご自身のVS Codeから送信すれば `gh auth login` は不要です。
5. **公開を確認**
   - GitHubリポジトリの **Actions** で **Deploy Supabase API** が成功し、Cloudflare Pagesの **Deployments** も成功するまで待ちます。GitHubへのpush後、両方とも自動で実行されます。
   - `https://<手順1で設定したProject name>.pages.dev/` を開きます。大会作成後に発行される `r/<ID>` 付きURLを閲覧者へ共有してください。

速報画面は無料枠の利用量を抑えるため15秒間隔で同期します。記録は端末のボタン操作と端末間の時刻同期による速報値です。操作・通信環境による誤差があり、自動カメラ判定や公認計時を行うものではありません。

## ロゴ素材

ヘッダーのSOKUHOロゴは独自作成のSVGです。全ページ下部にはスポンサー欄を固定表示しています。

- 筑波大学: 公式サイトのロゴSVG: https://www.tsukuba.ac.jp/assets/img/common/logo-w.svg
- NISHI: 株式会社ニシ・スポーツ公式サイトのロゴSVG: https://www.nishi.com/cms/nishi/common/images/logo_nishi_wh.svg
- New Balance: Simple IconsのSVG（CC0）: https://github.com/simple-icons/simple-icons/blob/develop/icons/newbalance.svg
- Cramer Japan: 公式サイトのロゴGIF: https://www.cramer.co.jp/cgi-bin/wordpress/wp-content/uploads/2014/03/logomain.gif
- GitHub: GitHub公式ロゴ配布のマークPNG: https://github.githubassets.com/images/modules/logos_page/GitHub-Mark.png

ヘッダーでは右側に筑波大学ロゴと「supported by」およびNISHIロゴを表示しています。スポンサー表示は各ロゴの形状・配色を変更せず、表示サイズのみ調整しています。公開利用は各社のブランドガイドラインと使用許諾に従ってください。