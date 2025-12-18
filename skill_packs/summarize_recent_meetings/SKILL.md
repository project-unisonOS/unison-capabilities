# summarize_recent_meetings (skill pack)

Goal: summarize recent meetings without leaking sensitive details.

Steps (planner-facing):
1. Resolve and enable a calendar connector (OAuth required).
2. Fetch recent event metadata (titles, times, attendees) within an explicit time window.
3. Generate a summary with:
   - key themes (if meeting notes/transcripts exist in storage)
   - action items (explicitly attributed only if present in notes)
4. Store the summary in `unison-context` as non-sensitive metadata; store any transcripts/attachments in `unison-storage`.

