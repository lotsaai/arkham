# Models may not pick models for subagents
One model cannot pick another model for running subagent unless the user explicitly approves the agent

# TODO comments need a reference
A `TODO` or `FIXME` comment must name a ticket or issue, for example `TODO(APP-123): ...`. A bare `TODO` is a violation.

# No hardcoded secrets
Source code must not contain passwords, API keys, or tokens. They come from configuration or a secrets manager. A test fixture
with an obviously fake value such as `test-key` is fine.

# Boolean names read as a question
A boolean variable or property starts with `is`, `has`, `should`, `can`, or a similar predicate prefix, for example
`is_enabled`, not `enabled`.

# New exported functions get a test
paths: crates/src/**
A newly added exported function or class comes with at least one test that exercises its main behaviour. Changing an
existing function does not require a new test by itself.

# Comments explain why, not what
A comment states a reason, a constraint, a workaround, or a non-obvious invariant. A comment that restates what the next line
plainly does is a violation.

# No commented-out code
Delete code that is no longer used. Do not leave it behind as comments.

# Migrations are reversible
paths: **/migrations/**
Every migration has a down step (or an explicit note in the file that the change cannot be reversed and why).
