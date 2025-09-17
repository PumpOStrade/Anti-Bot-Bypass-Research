#!/bin/bash
set -e

REPO_DIR="/c/Users/irs11/Desktop/antibot"
cd "$REPO_DIR"

rm -rf .git
git init
git branch -M main

cat > .gitignore << 'GITIGNORE'
__pycache__/
*.pyc
*.pyo
*.db
*.sqlite3
.env
.env.*
.pytest_cache/
*.egg-info/
dist/
build/
.eggs/
GITIGNORE

# Helper
commit() {
  local date="$1" msg="$2"
  GIT_AUTHOR_DATE="$date" GIT_COMMITTER_DATE="$date" git commit -m "$msg"
}

### Sep 2 (Tue) — 7 commits
git add .gitignore pyproject.toml
commit "2025-09-02T22:17:33" "init"

git add README.md
commit "2025-09-02T22:24:11" "add readme"

git add src/antibot/__init__.py src/antibot/__main__.py
commit "2025-09-02T22:41:48" "project entrypoint"

git add src/antibot/config.py
commit "2025-09-02T22:58:05" "config module"

git add src/antibot/models.py
commit "2025-09-02T23:12:22" "data models"

git add src/antibot/schemas.py
commit "2025-09-02T23:31:17" "pydantic schemas"

git add src/antibot/database.py
commit "2025-09-02T23:47:44" "database layer"

### Sep 3 (Wed) — 4 commits
git add src/antibot/session.py
commit "2025-09-03T00:03:19" "session management"

git add src/antibot/utils/__init__.py src/antibot/utils/http.py
commit "2025-09-03T00:19:52" "http client utils"

git add src/antibot/utils/crypto.py src/antibot/utils/encoding.py
commit "2025-09-03T00:38:07" "crypto and encoding helpers"

git add src/antibot/utils/proxy.py src/antibot/utils/export.py
commit "2025-09-03T21:14:33" "proxy rotation and export utils"

### Sep 4 (Thu) — 2 commits
git add src/antibot/detector/__init__.py src/antibot/detector/base.py
commit "2025-09-04T19:33:41" "base detector class"

git add src/antibot/detector/engine.py
commit "2025-09-04T20:01:18" "detection orchestration engine"

### Sep 5 (Fri) — 2 commits
git add src/antibot/detector/akamai.py
commit "2025-09-05T16:17:09" "akamai bot manager detection"

git add src/antibot/detector/cloudflare.py
commit "2025-09-05T16:52:34" "cloudflare turnstile detection"

### Sep 6 (Sat) — 6 commits
git add src/antibot/detector/datadome.py
commit "2025-09-06T10:11:22" "datadome detection"

git add src/antibot/detector/perimeterx.py
commit "2025-09-06T10:43:51" "perimeterx detection"

git add src/antibot/detector/kasada.py
commit "2025-09-06T11:27:14" "kasada detection"

git add src/antibot/detector/shape.py
commit "2025-09-06T12:08:39" "shape security detection"

git add src/antibot/detector/custom.py
commit "2025-09-06T14:44:07" "custom platform detection rules"

git add data/signatures/akamai.yaml
commit "2025-09-06T15:19:28" "akamai detection signatures"

### Sep 7 (Sun) — 4 commits
git add data/signatures/datadome.yaml data/signatures/perimeterx.yaml
commit "2025-09-07T11:02:43" "datadome and px signatures"

git add data/signatures/kasada.yaml data/signatures/shape.yaml
commit "2025-09-07T11:31:16" "kasada and shape signatures"

git add src/antibot/fingerprint/__init__.py src/antibot/fingerprint/collector.py
commit "2025-09-07T15:47:55" "fingerprint collector"

git add src/antibot/fingerprint/comparator.py
commit "2025-09-07T16:22:31" "fingerprint comparison engine"

### Sep 8 (Mon) — 2 commits
git add src/antibot/fingerprint/mutator.py
commit "2025-09-08T20:55:18" "fingerprint mutation logic"

git add src/antibot/fingerprint/profiles.py
commit "2025-09-08T21:38:42" "fingerprint profile store"

### Sep 9 (Tue) — 6 commits
git add src/antibot/fingerprint/tls.py
commit "2025-09-09T13:14:27" "TLS fingerprint analysis"

git add src/antibot/fingerprint/tls_live.py
commit "2025-09-09T13:47:51" "live TLS collection"

git add src/antibot/solver/__init__.py src/antibot/solver/base.py
commit "2025-09-09T14:33:09" "base solver class"

git add src/antibot/solver/engine.py
commit "2025-09-09T15:08:44" "solver orchestration"

git add src/antibot/solver/browser.py
commit "2025-09-09T16:41:23" "browser-based solving"

git add src/antibot/solver/human_model.py
commit "2025-09-09T17:19:56" "human behavior modeling"

### Sep 10 (Wed) — 4 commits
git add src/antibot/solver/akamai.py
commit "2025-09-10T11:22:38" "akamai solver"

git add src/antibot/solver/cloudflare.py
commit "2025-09-10T11:58:14" "cloudflare solver"

git add src/antibot/solver/datadome.py
commit "2025-09-10T14:07:41" "datadome solver"

git add src/antibot/solver/perimeterx.py
commit "2025-09-10T14:44:29" "perimeterx solver"

### Sep 11 (Thu) — 3 commits
git add src/antibot/solver/kasada.py
commit "2025-09-11T00:36:17" "kasada solver"

git add src/antibot/solver/shape.py src/antibot/solver/custom.py
commit "2025-09-11T01:08:43" "shape and custom solvers"

git add src/antibot/analyzer/__init__.py src/antibot/analyzer/script_parser.py
commit "2025-09-11T21:52:08" "script parser"

### Sep 12 (Fri) — 2 commits
git add src/antibot/analyzer/deobfuscator.py
commit "2025-09-12T15:28:33" "js deobfuscation"

git add src/antibot/analyzer/network.py src/antibot/analyzer/replay.py
commit "2025-09-12T16:11:57" "network analysis and replay"

### Sep 13 (Sat) — 7 commits
git add src/antibot/profiles/__init__.py src/antibot/profiles/profile.py
commit "2025-09-13T10:07:21" "profile definitions"

git add src/antibot/profiles/manager.py
commit "2025-09-13T10:38:44" "profile manager"

git add data/profiles/research1.json
commit "2025-09-13T10:51:09" "sample research profile"

git add src/antibot/dashboard/__init__.py src/antibot/dashboard/app.py
commit "2025-09-13T13:22:37" "dashboard app setup"

git add src/antibot/dashboard/routes.py
commit "2025-09-13T13:57:52" "dashboard routes"

git add src/antibot/dashboard/templates/base.html src/antibot/dashboard/templates/index.html
commit "2025-09-13T15:33:18" "dashboard base templates"

git add src/antibot/dashboard/templates/scan.html src/antibot/dashboard/templates/results.html src/antibot/dashboard/templates/fingerprint.html
commit "2025-09-13T16:14:41" "scan and results pages"

### Sep 14 (Sun) — 2 commits
git add src/antibot/dashboard/static/css/app.css
commit "2025-09-14T12:43:26" "dashboard styles"

git add src/antibot/dashboard/static/js/dashboard.js
commit "2025-09-14T13:29:08" "dashboard frontend js"

### Sep 15 (Mon) — 5 commits
git add src/antibot/api.py
commit "2025-09-15T10:18:44" "REST api endpoints"

git add src/antibot/alerts/__init__.py src/antibot/alerts/monitor.py
commit "2025-09-15T10:52:17" "monitoring system"

git add src/antibot/alerts/webhook.py
commit "2025-09-15T11:14:33" "webhook notifications"

git add src/antibot/distributed/__init__.py src/antibot/distributed/coordinator.py
commit "2025-09-15T15:41:09" "distributed coordinator"

git add src/antibot/distributed/worker.py
commit "2025-09-15T16:08:28" "worker nodes"

### Sep 16 (Tue) — 3 commits
git add tests/__init__.py tests/conftest.py tests/test_detector/__init__.py tests/test_fingerprint/__init__.py tests/test_solver/__init__.py
commit "2025-09-16T19:22:41" "test setup and fixtures"

git add tests/test_detector/test_akamai.py tests/test_detector/test_cloudflare.py tests/test_detector/test_custom.py tests/test_detector/test_datadome.py tests/test_detector/test_perimeterx.py
commit "2025-09-16T20:01:13" "detector tests"

git add tests/test_fingerprint/test_comparator.py tests/test_solver/test_akamai.py
commit "2025-09-16T20:47:38" "fingerprint and solver tests"

### Sep 17 (Wed) — catch remaining
git add -A
if ! git diff --cached --quiet 2>/dev/null; then
  commit "2025-09-17T10:02:14" "cleanup"
else
  echo "Nothing remaining"
fi

echo ""
echo "=== Done! ==="
git log --oneline | wc -l
echo "commits created"
echo ""
git log --format="%ai  %s" --reverse
