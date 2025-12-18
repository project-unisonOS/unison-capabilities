# system_diagnostics_summary (skill pack)

Goal: produce a bounded local diagnostics summary for troubleshooting.

Steps (planner-facing):
1. Run `host.info`, `host.resources`, and `host.net_ifaces`.
2. Optionally run `process.list` with a bounded limit.
3. Summarize results (no secrets; no large payloads).
4. Store summary as an internal diagnostic record.

