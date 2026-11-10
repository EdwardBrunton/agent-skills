---
name: red-team
description: Multi-persona security review — parallel specialist lenses, then a red team chains the findings into attack paths.
disable-model-invocation: true
---

# Red Team Review

Each selected persona runs as its own `task` call, all in one response, then a single
red-team agent chains the raw findings into attack paths. Isolation is the method: a
generalist pass anchors on what it notices first; each specialist hunts its own class
exhaustively; the red team prioritises. Security only: style, quality, and architecture
are out of scope.

## Step 1 — Scope

Default to **diff scope**; full audit only when asked.

- PR: `gh pr diff <n>`, plus `gh pr view <n> --json title,body,files,baseRefName`.
- Branch: `git diff <base>...<branch>`, where `<base>` is the branch's PR base, else the
  repo's default branch.
- Uncommitted work: `git diff HEAD`.
- Full audit: map the attack surface — entry points (controllers/routes/handlers/consumers/
  jobs/CLI), authn/authz mechanisms, data stores and their access layer, secret sources,
  outbound calls, file/upload handling, deployment config (IaC, containers, CI).

In diff scope, save the diff to a file outside the repo; the agents are read-only and read
it from there.

**Done when** scope is a concrete file list, plus the saved diff's path in diff scope.

## Step 2 — Threat model and select personas

One fast pass over the scope. Write a **threat model** block; it is pasted into every
agent prompt:

- **Assets** — what an attacker wants (data, funds, access, availability)
- **Entry points** — where untrusted input enters
- **Trust boundaries** — where privilege changes
- **Attacker positions** — unauthenticated, low-privilege user, other tenant, insider

| Persona | Lens | Select when scope touches |
|---------|------|---------------------------|
| `authz-agent` | Broken access control, IDOR, tenant isolation, privilege escalation, token handling | An authenticated surface: endpoint, handler, consumer, token or session code |
| `injection-agent` | SQL/HQL/NoSQL, command, XSS, deserialization, path traversal, SSRF, XXE | Untrusted input reaching a query, command, markup, path, URL fetch, or parser |
| `secrets-crypto-agent` | Hardcoded credentials, config leakage, weak/misused crypto, TLS | Config or env files; crypto, hashing, token generation, or TLS code |
| `data-exposure-agent` | PII leakage, over-returning entities, sensitive data in logs and errors | Response models, serialization, logging, telemetry, error handling, personal-data storage |
| `supply-chain-agent` | Vulnerable dependencies, lockfile drift, CI/CD and build pipeline risk | Manifests, lockfiles, registry config, workflows, build scripts |
| `logic-abuse-agent` | Validation gaps, races/TOCTOU, workflow bypass, client-trusted values | State-changing handlers, multi-step workflows, money, quotas, counters |
| `defensive-controls-agent` | Auditing, rate limiting, fail-open error handling, headers, CORS/CSRF | Auth flows, state-changing web endpoints, the middleware pipeline, uploads, outbound calls |
| `misconfig-agent` | Environment gating, exposed dev/ops surfaces, container/IaC/cloud settings, defaults | Hosting or deployment config, IaC, container files, environment-keyed branches |

A full audit selects all eight.

**Done when** every entry point is assigned to at least one persona or its skip is stated,
and every persona whose trigger matches is selected. Tell the user the selection and any
skips in one line.

## Step 3 — Load context

Agents read their own material by path, so resolve absolute paths rather than pasting:

- `references/personas.md` in this skill's directory. Read its Shared Evidence Contract
  yourself; Step 6 applies it.
- `references/dotnet-security.md` when scope contains C#/.NET files, and
  `references/react-typescript-security.md` when it contains TS/TSX/JS.
- The repo's instruction files that exist (`.github/copilot-instructions.md`,
  `.github/instructions/*.instructions.md`).

When `supply-chain-agent` is selected, run the audit tools that fit the scope and save
their output beside the diff: `dotnet list package --vulnerable --include-transitive`,
`npm audit --omit=dev` (or `pnpm audit` / `yarn npm audit`), `pip-audit`,
`gh api repos/{owner}/{repo}/dependabot/alerts`.

**Done when** you hold every path above, and the audit output's path or the reason no
audit could run.

## Step 4 — Wave 1

One `task` call per selected persona, all in this one response, `mode: background`,
agent type `security-review`. Fill the template per agent.

```
You are the {persona name} in a multi-persona security review of {PR #N / the {repo} codebase}.
Review ONLY through your lens — other personas cover the other classes.

READ FIRST, in full:
- {absolute path of references/personas.md} — the sections "Shared Evidence Contract"
  and "{persona name}"
- {absolute path of each stack reference that applies} — the section headed with your
  persona name
- {absolute paths of the instruction files that exist} — repository conventions. A
  violation with a security consequence is a finding; one without is out of scope.

THREAT MODEL:
{the threat model block from Step 2}

SCOPE: {diff | full audit}
{files in scope}
{path of the saved diff, or the entry points to start from}
{supply-chain-agent only: path of the audit output, or why no audit could run}

METHOD:
- Read the actual code: the surrounding file, the caller, and any middleware/base
  class/filter, before concluding a control is missing or applied.
- Trace source -> sink: name the untrusted input, every transform, and the sink.

REPORT in the contract's report format: FINDINGS, LEADS, CONTROLS RELIED ON.
A clean lens is a valid result — state it plainly.
```

Then end the turn. **Done when** every agent's notification has arrived and been read once.

## Step 5 — Wave 2

One `red-team-agent` (`security-review`, background) told to read the "Shared Evidence
Contract" and "`red-team-agent`" sections of `references/personas.md` by path, and given
the threat model, the scope (files and diff path), and every wave-1 report verbatim:
findings, leads, and controls relied on. It reads code to chain them and probe the seams
between lenses; the persona sweeps are done.

**Done when** its report classifies every wave-1 finding as chained, re-rated, kept, or
dropped, every lead as chained or dropped, and ranks what it would exploit first.

## Step 6 — Consolidate

1. **Deduplicate** — the same issue from two personas is one finding; note the
   corroboration and raise confidence.
2. **Apply the red team's re-rating** — it saw the whole picture.
3. **Keep** findings that meet the contract; a lead survives only as a hop in a chain.
4. **Verify** — open the file for every CRITICAL and HIGH, every hop of an attack chain,
   and every inter-lens gap the red team traced itself, and confirm the line and the
   mechanism in the source. The report's accuracy is yours.

**Done when** every surviving finding is deduplicated and carries its final severity, and
every item under 4 is confirmed in source or dropped.

## Step 7 — Report

Present a table with columns `# | Severity | File | Lines | Vulnerability | Confidence`
(🔴 CRITICAL 🟠 HIGH 🟡 MEDIUM ⚪ LOW), then:

- **Attack chains** — ordered hops with `file:line`
- **Coverage** — personas run, personas skipped and why, scope chosen
- **Clean lenses** — stated explicitly so the user knows they were checked

Offer follow-up with `ask_user`: fix highest-severity, fix all, write `SECURITY-REVIEW.md`,
or stop. Reporting is the terminal step until the user chooses; secret values stay out of
every report, commit, and issue.

**Done when** the report is presented and the user has chosen a follow-up.

## Step 8 — Fix (on approval)

- Independent fixes in parallel `general-purpose` agents; dependent fixes sequentially.
- Build and run the existing tests; add a regression test where the project has a natural
  place for one.
- Report what was fixed and what was consciously left.

**Done when** build and tests pass and each fix has been re-traced to confirm the path is
closed rather than moved.
