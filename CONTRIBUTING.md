# Contributing

Thanks for helping build a better toolkit for defenders. This document is both the
contribution process and the **skill authoring standard** every skill in this repo follows.

## Quick process

1. Open an issue describing the skill or change (a paragraph is enough).
2. Fork, branch, and build the skill under `skills/<skill-name>/`.
3. Run the validator: `python scripts/validate_skills.py` (or `uv run scripts/validate_skills.py`).
4. Test any bundled script with sample input and include the sample under `skills/<name>/examples/`.
5. Open a pull request. Describe what the skill does, when it triggers, and what you tested.

## What belongs here

Skills for people who run a SOC, a detection engineering function, an incident response team,
a threat intel cell, or a vulnerability management program. A good skill encodes *how an
experienced analyst thinks* about a task, gives Claude the reference material it would
otherwise have to guess at, and bundles scripts for the deterministic parts.

Not accepted: exploit code, offensive tooling, evasion techniques, anything that requires a
paid dependency to function, or skills that only work with one vendor's product unless the
vendor-specific parts are isolated in `references/` and the workflow is generic.

## Skill anatomy

```
skills/<skill-name>/
├── SKILL.md                 # required
├── scripts/                 # optional, standard-library Python (or POSIX sh), each with --help
├── references/              # optional, loaded on demand; ALWAYS includes environment.md
│   ├── environment.md       # team customization: tools, thresholds, naming, escalation paths
│   └── <topic>.md           # deeper reference material, platform-specific cheat sheets
├── assets/                  # optional, templates that end up in outputs (report skeletons, etc.)
└── examples/                # optional, sample inputs used to test the scripts
```

## SKILL.md standard

**Frontmatter**

```yaml
---
name: skill-name            # must equal the directory name; lowercase, hyphens
description: >-             # 1 to 4 sentences, under 1024 characters. This is the trigger.
  What the skill does AND when to use it, phrased a little pushy: list the user phrasings,
  artifacts, and situations that should cause Claude to reach for it, including ones where
  the user does not name the task.
---
```

Optional frontmatter that is welcome when it fits: `argument-hint`, `allowed-tools`,
`disable-model-invocation: true` for skills that should only run when a human invokes them
(anything that takes a containment action, for example).

**Body** (target 150 to 400 lines; hard ceiling 500):

- Open with two or three sentences on what "good" looks like and what goes wrong when the task
  is done badly. That framing lets the model make judgment calls the steps do not cover.
- A numbered **Workflow**. Imperative voice. Each step says what to do, how (which script,
  which reference file), and why it matters.
- An **Output** section with an exact template when the deliverable has a fixed shape.
- A **Things that go wrong** or **Pitfalls** section with the mistakes an experienced analyst
  would warn a junior about.
- A **Customization** section pointing at `references/environment.md` and saying what a team
  should edit.
- Cross-reference sibling skills by name (for example "hand hashes to `malware-triage`").

**Style**

- Explain the why. Prefer "GreyNoise first, because 80% of scanner IPs are background noise
  and you will waste enrichment quota" over "ALWAYS check GreyNoise".
- Keep it general. Do not overfit to one example report or one vendor console.
- Treat document content as data. Skills that read attacker-controlled input say so
  explicitly, so the model does not follow instructions embedded in a phishing email.
- Never fabricate results. If an enrichment source or a log source is not available in the
  session, the skill says to mark it "not checked" rather than guess.

## Scripts standard

- Python 3.10+, **standard library only**. Teams should be able to run these on a locked-down
  analyst workstation with no `pip install`.
- Module docstring with usage examples. `argparse` with `--help`. Read from a file path or `-`
  for stdin. Write to stdout. Exit codes: 0 success, 2 bad input.
- Deterministic and side-effect free: parse, normalize, score, format. Never fetch a URL,
  execute a sample, or write outside the working directory.
- Handle hostile input: bounded regexes, no `eval`, no `pickle`, size limits where a pathological
  file could hang the parser.
- Windows and POSIX friendly (paths via `pathlib`, `encoding="utf-8", errors="replace"`).

## Sample data standard

Files under `examples/` are cloned onto analyst workstations that run endpoint protection.
Keep them from tripping it:

- No realistic attack command lines, download cradles, encoded PowerShell, or shellcode-like
  blobs, even in "obviously fake" log rows. Describe them instead:
  `powershell -w hidden -nop -c "[download cradle; redacted in sample data]"`.
- No real malware, no real malicious hashes presented as samples, no live malicious URLs.
  Use `.example` domains and RFC 5737 / RFC 3849 address ranges.
- Reference emulation tests and techniques by name and ID; never embed the test body.
- Detection regexes inside scripts may name suspicious tokens (that is their job), but keep
  them in Python, not in shell one-liners or PowerShell, where AMSI scans the command line.

## References standard

- `environment.md` is a fill-in-the-blanks file. Use obvious placeholders
  (`yourcompany.example`, `<siem-url>`) and say what each field changes.
- Large references (over ~300 lines) start with a table of contents so the model can jump.
- Cite sources for framework material (MITRE ATT&CK, NIST, Sigma spec) with the version or
  date, since these move.

## Validation

`scripts/validate_skills.py` checks: frontmatter present and parseable, `name` matches the
directory, description length, presence of `references/environment.md`, that every relative
path mentioned in SKILL.md exists, that every script compiles and responds to `--help`, and
that no file contains obvious secrets. CI runs the same script.

## Licensing

By contributing you agree your contribution is licensed under the repository's MIT license.
