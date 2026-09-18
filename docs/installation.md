# Installation

Skills are plain folders. There are three ways to get them into Claude Code, from easiest to
most controlled.

## 1. Plugin (recommended)

Inside Claude Code:

```
/plugin marketplace add ftrout/secops-claude-skills
/plugin install secops-skills@secops-claude-skills
```

Skills then appear as `/secops-skills:<skill-name>` and Claude will also invoke them
automatically when a task matches a skill's description. Update later with
`/plugin update secops-skills`.

Pin to a tag or commit for production use; `main` moves.

## 2. Copy into a skills directory

Personal (all projects):

```sh
git clone https://github.com/ftrout/secops-claude-skills
cd secops-claude-skills
./scripts/install.sh            # POSIX
.\scripts\install.ps1           # Windows PowerShell
```

Project-scoped (checked into your repo, shared with the team):

```sh
./scripts/install.sh --project  # writes to ./.claude/skills
```

Pick a subset: `./scripts/install.sh ioc-extraction phishing-analysis`.
Use `--link` (`-Link` on Windows) to symlink instead of copy so edits in the clone take
effect immediately.

## 3. Vendor into your own repo

Fork this repository, delete the skills you do not want, edit each
`references/environment.md` with your tooling, and install from your fork with the plugin
route. This is the best option for teams, because customizations live in version control
and a pull request review protects the shared skills.

## Requirements

- Claude Code (CLI, desktop, or IDE extension) with skills support.
- Python 3.10 or newer on the machine where the bundled scripts run. Every script is
  standard-library only; nothing to `pip install`. If you do not have a system Python,
  [uv](https://docs.astral.sh/uv/) works: `uv run --no-project python <script>`.

## Verifying

```sh
python scripts/validate_skills.py
python scripts/smoke_test.py
```

Both should report zero problems. In Claude Code, type `/` and confirm the skills are listed.
