"""The web interface (DESIGN.md §14, Phase 5): for people who won't use a command
line. An optional extra: `pip install -e '.[web]'`. Pages read through the
code the report and `checker fleet` use, and open the evidence store read-only. Django's
own database, web.db in the home, holds only accounts, sessions, what limits guessing, the setup
link's hash and the activity record."""
