# Rules for working in this repository

## This repository is PUBLIC. Never publish internal data. This rule overrides everything else.

Nothing that identifies a customer, a person, or our deployment may appear in anything that
reaches GitHub: commits, code, tests, fixtures, README, issues, pull requests, review comments,
commit messages, workflow logs or summaries.

Never publish:

- e-mail addresses or names of real people (users, admins, customers), not even as log examples
- customer or organisation codes and names (realm names, group codes, tenant aliases, client IDs)
- hostnames, URLs, IP addresses, domains of our or our customers' systems
- realm exports, configuration dumps, token contents, log excerpts from real systems
- counts or facts derived from internal configuration (number of IdPs, groups, users, mappers)
- rollout dates, ticket numbers, internal project names

Use neutral placeholders instead: `jane.doe@example.org`, `ORG`, `SSO/ORG/team-a`, `upstream`,
`example.test`. The company name "SIT" (we are Südwestfalen-IT, the repository owner) is fine.

Before every commit, push, issue, PR description or comment: re-read the text once with only
this question in mind. If internal data is needed to explain something, explain it to the user in
the chat, not on GitHub. If in doubt, leave it out and ask.

Material the user shares in the conversation (realm exports, log lines, configs) is for
analysis only and never a source of example data.
