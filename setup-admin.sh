#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

printf '管理者のメールアドレスを入力してください: '
IFS= read -r ADMIN_EMAIL

printf '管理者パスワードを入力してください（12文字以上・入力中は表示されません）: '
IFS= read -r -s ADMIN_PASSWORD
printf '\n'

if [[ -z "$ADMIN_EMAIL" ]]; then
  printf 'メールアドレスが空です。もう一度実行してください。\n' >&2
  exit 1
fi

if [[ ${#ADMIN_PASSWORD} -lt 12 ]]; then
  printf 'パスワードは12文字以上にしてください。もう一度実行してください。\n' >&2
  exit 1
fi

export ADMIN_EMAIL ADMIN_PASSWORD
node server.js