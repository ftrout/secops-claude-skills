# Lessons learned: <INC-YYYY-NNNN> <short title>

**Session:** <YYYY-MM-DD>, facilitator <name>, attendees <roles>
**Ground rules:** Blameless. We assume everyone acted reasonably with the information and
tools they had at the time. We examine decisions and systems, not people. "Why did the
system make that the reasonable choice?" replaces "why did you do that?".

## 1. Incident recap (5 minutes)
<Two paragraphs from the post-incident report: what happened, impact, key intervals
(dwell, time to detect, time to contain).>

## 2. Timeline walk-through of decisions
For each key decision point, capture what was known at the time, what was decided, and
what we would want to be different.

| Time (UTC) | Decision / event | What was known then | Outcome | Would we change it? |
|---|---|---|---|---|

## 3. What went well
<Be specific and attribute to a system, runbook, or practice so it can be repeated.>
-

## 4. What went poorly
<Specific, factual, blameless. "The alert sat unowned for 3 hours because the queue view
does not surface P2s on weekends" rather than "the analyst missed it".>
-

## 5. Where we got lucky
<Things that went right by chance rather than design. These are the most important
findings because luck does not repeat.>
-

## 6. Contributing factors
Group under: detection gap, visibility gap (logs/retention), tooling, process/runbook,
training/awareness, architecture/hardening, vendor/third party, communication.

| Factor | Category | Evidence from the timeline |
|---|---|---|

## 7. Action items
Every item has one owner and a date. Prefer few, funded actions over a long wish list.
Tag with the phase it improves.

| # | Action | Phase (prevent / detect / respond / recover / comms) | Owner | Due | Tracking ref |
|---|---|---|---|---|---|

## 8. Metrics to watch
<What would show these actions worked: time-to-detect for this alert class, coverage for
the technique in `purple-team-exercise`, rule hit rates from `detection-engineering`.>

## 9. Follow-up
- Report distribution: <list>
- Action-item review date: <YYYY-MM-DD>
- Related incidents / patterns: <INC-...>
