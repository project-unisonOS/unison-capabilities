# email_find_and_draft_response (skill pack)

Goal: find a relevant email thread and draft a response (draft-only).

Steps (planner-facing):
1. Resolve and enable an email connector (OAuth required).
2. Search for emails matching a user-provided query (subject/sender/time range).
3. Retrieve only the minimum content required to draft (avoid attachments unless needed).
4. Draft a response; do not send without explicit user confirmation.
5. Persist the draft reference (not content) in context where appropriate.

