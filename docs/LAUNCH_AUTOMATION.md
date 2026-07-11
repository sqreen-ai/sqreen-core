# Launch automation

Sqreen can **partially automate** open-source launch posts. Full hands-off posting to every platform is not realistic (X API costs, HN anti-spam rules, LinkedIn app review).

## What runs automatically

| Trigger | What happens |
|---------|----------------|
| **GitHub Release published** (`v*`) | Renders all platform copy, uploads CI artifact, creates GitHub Discussion (Announcements) |
| **workflow_dispatch** | Same, with optional Bluesky post |

Workflow: [`.github/workflows/announce-release.yml`](../.github/workflows/announce-release.yml)

## What stays manual (by design)

| Platform | Why | What you do |
|----------|-----|-------------|
| **X / Twitter** | API is paid; account bans for pure bots | Download artifact → paste `x.txt` (or add `X_*` secrets — see below) |
| **Hacker News** | Show HN must be human-submitted | [news.ycombinator.com/submit](https://news.ycombinator.com/submit) — title + URL from artifact |
| **LinkedIn** | API restricted | Paste `linkedin.txt` |
| **Reddit** | Subreddit rules vary | Optional — set `REDDIT_*` secrets if you want to extend the workflow |

## One-time setup

### 1. Enable Discussions

Repo **Settings → General → Features → Discussions** (already on for sqreen-core).

The workflow needs an **Announcements** category (default on most repos).

### 2. Optional: auto-post Bluesky

Repo **Settings → Secrets**:

- `BLUESKY_HANDLE` — e.g. `sqreen.bsky.social`
- `BLUESKY_APP_PASSWORD` — app password from Bluesky settings

Repo **Settings → Variables**:

- `POST_TO_BLUESKY` = `true` (auto-post on every release)

### 3. Optional: X API (advanced)

Add secrets and extend the workflow if you have X API Basic access:

- `X_API_KEY`, `X_API_SECRET`, `X_ACCESS_TOKEN`, `X_ACCESS_SECRET`

We recommend **Typefully** or **Buffer** for X scheduling instead — paste from the artifact.

## Local use

```bash
# Render posts for a version
bash scripts/render-launch-posts.sh v0.1.11

# Output: launch/rendered/v0.1.11/
#   x.txt, hn-*.txt, linkedin.txt, bluesky.txt, github-discussion-*.md, ...
```

Edit copy in [`launch/templates.yaml`](../launch/templates.yaml), then re-render.

## Manual trigger (no new release)

```bash
gh workflow run announce-release.yml \
  --repo sqreen-ai/sqreen-core \
  -f version=v0.1.11 \
  -f create_discussion=true \
  -f post_bluesky=false
```

Download the **launch-posts-v0.1.11** artifact from the Actions run.

## Suggested launch sequence

1. Tag and push release (`v*` → builds binaries + GitHub Release).
2. **announce-release** workflow runs → Discussion + artifact.
3. You post **X** + **Show HN** within 24h (copy from artifact or Actions summary).
4. Pin the GitHub Discussion in the UI.
5. Optional: LinkedIn, Reddit, Dev.to from artifact files.

## Customize copy

All placeholders in `launch/templates.yaml`:

- `{{version}}` — release tag
- `{{release_url}}` — GitHub release page
- `{{repo_url}}` — repository URL
- `{{site_url}}` — https://sqreen.ai
- `{{install_cmd}}` — one-line install

After org rename, defaults use `sqreen-ai/sqreen-core`.
