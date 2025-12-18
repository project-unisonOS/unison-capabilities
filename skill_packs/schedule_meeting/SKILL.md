# schedule_meeting (skill pack)

Goal: propose a safe, policy-aware meeting scheduling flow using available calendar/email capabilities.

Steps (planner-facing):
1. Resolve calendar capability (e.g., `connector.google.calendar`) and ensure it is enabled; if disabled, request OAuth onboarding.
2. Query availability for proposed participants (do not send invites yet).
3. Propose 2–3 candidate slots to the user and request confirmation.
4. Upon confirmation, create the calendar event and draft an email invitation (draft-only unless explicitly approved).

Notes:
- This is a planning artifact. The planner is responsible for executing individual capabilities.
- Store any OAuth tokens in secrets backend; manifests hold references only.

