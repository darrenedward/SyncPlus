# Issue tracker: GitHub

Issues and specifications for this repository live in GitHub Issues at `darrenedward/SyncPlus`. The repository is public. Use the `gh` CLI for issue operations and configure Git remotes to use SSH.

## Conventions

- Create an issue with `gh issue create --title "..." --body "..." --label "ready-for-agent"`.
- Read an issue with `gh issue view <number> --comments` and inspect labels.
- List issues with `gh issue list --state open --json number,title,body,labels,comments`.
- Apply or remove labels with `gh issue edit <number> --add-label "..."` or `--remove-label "..."`.
- Close an issue with `gh issue close <number> --comment "..."`.

External pull requests are not a triage request surface for this repository. They may still be reviewed and merged through the normal GitHub workflow.
