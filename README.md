# agent-skills

Agent skills packaged for [APM](https://github.com/microsoft/apm) (Agent Package Manager).

## Install

For your user, so the skills are available in every repo:

```sh
apm install EdwardBrunton/agent-skills -g
```

For a single project, from its root:

```sh
apm install EdwardBrunton/agent-skills
```

Restart your agent session afterwards so it picks up the skills.

## Skills

| Skill | What it does |
|-------|--------------|
| [`red-team`](.apm/skills/red-team/SKILL.md) | Multi-persona security review: parallel specialist lenses, then a red team chains the findings into attack paths. |

### red-team

Invoke it by name (`/red-team`); it is user-invoked only. It reviews a PR, a branch,
uncommitted work, or on request the whole codebase:

1. Builds a threat model and selects the personas that fit the scope.
2. Runs each persona as its own isolated agent: authz, injection, secrets and crypto, data
   exposure, supply chain, logic abuse, defensive controls, misconfiguration.
3. Hands every report to a red-team agent that chains findings into attack paths and
   re-rates them.
4. Verifies the serious findings in the source and reports them with coverage.

Stack-specific notes ship for C#/.NET and React/TypeScript; other stacks get the
language-agnostic briefs.

Written for GitHub Copilot CLI: it relies on `task` sub-agents of type `security-review`
and on `ask_user`.

## Layout

```
apm.yml                  package manifest
.apm/skills/<name>/      one folder per skill, each with a SKILL.md
```

## License

[MIT](LICENSE)
