---
name: skill-template
description: >-
  Replace this with what the skill does AND when to use it. List the phrases, artifacts, and
  situations that should trigger it, including cases where the user does not name the task
  explicitly. Keep under 1024 characters. Be a little pushy; Claude under-triggers skills.
---

# Skill Title

Two or three sentences: what a good result looks like, and what goes wrong when this task is
done badly. This framing is what lets the model make sensible judgment calls the steps below
do not anticipate.

## Workflow

1. **Gather inputs.** What to ask for or read. Which formats are expected.
2. **Run the deterministic part.** `python scripts/<tool>.py <input> --format json` and why it is
   better than eyeballing.
3. **Apply judgment.** The analytical step. Point to `references/<topic>.md` for the deep material.
4. **Produce the deliverable.** Point to the template in the Output section.
5. **Recommend next actions.** Who to notify, what to hunt, which sibling skill takes over.

## Output

Exact template when the deliverable has a fixed shape:

```markdown
# <Title>
## Summary
## Findings
## Recommended actions
```

## Things that go wrong

- Mistake an experienced analyst warns a junior about, and how to avoid it.
- Another one.

## Customization

Edit `references/environment.md` with your tooling, thresholds, naming conventions, and
escalation paths. Say which fields change the skill's behaviour.
