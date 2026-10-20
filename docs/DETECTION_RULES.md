# Detection rules and tuning results

## Signals
(5 rows: name, what it measures, window, the number that gives 1.0)

## Score and alerts
Weights, combo bonus, levels, gate, alert lifecycle (open / escalated / resolved, cooldown).

## Scenario results
Paste BOTH tables: the Day 6 profile (before) and the current profile (after).

## What I changed, and why
1. ignore_dirs: fixed git_checkout (trade-off: an ignored folder is a blind spot)
2. gate_signals: fixed three false alarms (cost: created a miss, see 3)
3. classify refinement: fixed that miss for renamed compressed files

## Known limitations
- compressed files encrypted in place with the same name (zip_same_name)
- ext_change blind to an attacker who reuses a common extension
- rename_burst blind to copy-delete (other signals cover it)
- app that writes many random files (cache_dat) is indistinguishable
- partial encryption of only the tail of a file
- reads can fail on files already renamed (TOCTOU), so the jump often shows on the MOVED line