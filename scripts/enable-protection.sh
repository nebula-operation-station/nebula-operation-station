#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Turns on the binding controls for main. Run once, after the repository
# has been made public (GitHub Free offers branch protection for public
# repositories only):
#
#   gh auth login                        # account with admin rights
#   scripts/enable-protection.sh nebula-operation-station/nebula-operation-station
#
# Single-maintainer setup: external pull requests need an approving review
# from a code owner; the maintainer, as admin, may merge his own reviewed
# PRs (GitHub never counts an author's own approval). Set ENFORCE_ADMINS=true
# once there is a second maintainer.
set -euo pipefail

repo="${1:?usage: $0 owner/repo}"
enforce_admins="${ENFORCE_ADMINS:-false}"

visibility=$(gh api "repos/${repo}" --jq .visibility)
if [[ "$visibility" != "public" ]]; then
  echo "enable-protection: ${repo} is ${visibility}; make it public first." >&2
  exit 1
fi

echo "==> Branch protection on main"
gh api -X PUT "repos/${repo}/branches/main/protection" --input - <<JSON
{
  "required_status_checks": {
    "strict": true,
    "contexts": ["test", "lint", "vuln", "protected-paths"]
  },
  "enforce_admins": ${enforce_admins},
  "required_pull_request_reviews": {
    "dismiss_stale_reviews": true,
    "require_code_owner_reviews": true,
    "required_approving_review_count": 1,
    "require_last_push_approval": true
  },
  "restrictions": null,
  "required_linear_history": false,
  "allow_force_pushes": false,
  "allow_deletions": false,
  "required_conversation_resolution": true
}
JSON

echo "==> Security features"
gh api -X PUT "repos/${repo}/vulnerability-alerts"
gh api -X PUT "repos/${repo}/automated-security-fixes"
gh api -X PUT "repos/${repo}/private-vulnerability-reporting"

echo "==> Label for approved protected-path changes (maintainers only)"
gh label create protected-change-approved --repo "$repo" --force \
  --color b60205 --description "Maintainer approved a change to a protected path" >/dev/null

echo "==> Result"
gh api "repos/${repo}/branches/main/protection" \
  --jq '{checks: .required_status_checks.contexts, codeowners: .required_pull_request_reviews.require_code_owner_reviews, dismiss_stale: .required_pull_request_reviews.dismiss_stale_reviews, force_push: .allow_force_pushes.enabled, admins: .enforce_admins.enabled}'
