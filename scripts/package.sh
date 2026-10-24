#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
raw="${1:-${GITHUB_REF_NAME:-dev}}"
version="${raw#v}"
name="simple-auth-${version}"
out="${root}/dist-release"
stage="${out}/${name}"

rm -rf "${out}"
mkdir -p "${stage}"

if command -v git >/dev/null 2>&1 && git -C "${root}" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  git -C "${root}" archive --format=tar HEAD | tar -C "${stage}" -xf -
else
  rsync -a \
    --exclude '.git/' \
    --exclude '.venv/' \
    --exclude 'data/' \
    --exclude 'dist-release/' \
    --exclude 'frontend/node_modules/' \
    --exclude 'frontend/dist/' \
    --exclude '__pycache__/' \
    --exclude '.DS_Store' \
    --exclude '.env' \
    "${root}/" "${stage}/"
fi

rm -rf \
  "${stage}/.venv" \
  "${stage}/data" \
  "${stage}/dist-release" \
  "${stage}/frontend/node_modules" \
  "${stage}/frontend/dist"

(
  cd "${out}"
  tar -czf "${name}.tar.gz" "${name}"
  if command -v zip >/dev/null 2>&1; then
    zip -qr "${name}.zip" "${name}"
  else
    python3 -c "import shutil; shutil.make_archive('${name}', 'zip', '${name}')"
  fi
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "${name}.tar.gz" "${name}.zip" > SHA256SUMS
  else
    sha256sum "${name}.tar.gz" "${name}.zip" > SHA256SUMS
  fi
)

rm -rf "${stage}"
echo "${out}/${name}.tar.gz"
echo "${out}/${name}.zip"
echo "${out}/SHA256SUMS"
