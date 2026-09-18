## What this changes

<!-- One or two sentences. If it adds a skill, say what job it does for an analyst. -->

## Type of change

- [ ] New skill
- [ ] Change to an existing skill (workflow, references, or output format)
- [ ] Bundled script fix or improvement
- [ ] Documentation or repository tooling
- [ ] Other:

## Checklist

- [ ] `python scripts/validate_skills.py` passes
- [ ] `python scripts/smoke_test.py` passes
- [ ] Checked against the support floor: `uv run --no-project --python 3.10 python scripts/validate_skills.py`
- [ ] Bundled scripts are standard library only, take `--help`, and read `-` for stdin
- [ ] `references/environment.md` exists and uses placeholders, not real values
- [ ] Example data is synthetic: `.example` domains, RFC 5737/3849 addresses, no real malware,
      no realistic attack command lines (see the sample data standard in CONTRIBUTING.md)
- [ ] No credentials, customer data, or employer-confidential material in any file or commit

## How you tested it

<!-- The commands you ran and what the output showed. For a skill, the prompts you tried
     and whether Claude picked the skill up on its own. -->

## Notes for the reviewer

<!-- Judgment calls, known gaps, anything you want a second opinion on. -->
