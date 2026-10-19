#!/usr/bin/env bash
# Bootstrap a fresh Ubuntu Lightsail instance to run the guarded agent service.
# Usage (on the instance):
#   export GH_PAT=ghp_xxx          # a GitHub token that can read the private repo
#   export OPENAI_API_KEY=sk-...   # the model the agent runs on
#   export AGENTGUARD_SECRETS='{"api":"...","ssh_pw":"..."}'   # values to protect (optional)
#   curl -fsSL <this file> | bash     # or: bash bootstrap.sh
set -euo pipefail

REPO="${REPO:-srics96/sricharans-personal-agent}"
APP_DIR="${APP_DIR:-$HOME/agent}"

# 1. Docker
if ! command -v docker >/dev/null; then
  curl -fsSL https://get.docker.com | sh
  sudo usermod -aG docker "$USER" || true
fi

# 2. Code (private repo via token)
if [ ! -d "$APP_DIR/.git" ]; then
  git clone "https://${GH_PAT}@github.com/${REPO}.git" "$APP_DIR"
fi
cd "$APP_DIR"
git pull || true

# 3. Build + run (port 8080). Secrets passed as env, never baked into the image.
sudo docker build -t guarded-agent .
sudo docker rm -f guarded-agent 2>/dev/null || true
sudo docker run -d --name guarded-agent --restart unless-stopped \
  -p 8080:8080 \
  -e OPENAI_API_KEY="${OPENAI_API_KEY}" \
  -e AGENTGUARD_SECRETS="${AGENTGUARD_SECRETS:-{}}" \
  -e AGENTGUARD_MODEL="${AGENTGUARD_MODEL:-gpt-4.1-mini}" \
  guarded-agent

echo "Service starting on :8080. Check:  curl http://localhost:8080/health"
