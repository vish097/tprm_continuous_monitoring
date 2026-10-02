# Architecture

One loop, repeated weekly for every control.

1. GitHub Actions wakes up on the Monday schedule (or on demand via workflow dispatch).
2. Each control script runs: it queries a source of truth (identity provider API, cloud API, HR roster export), evaluates the results against the control rule, and writes findings to `evidence/` in the standard findings schema.
3. Findings are committed back to the repo. The commit history is the audit trail: what was found, and when.
4. Next steps on the roadmap: open one GitHub issue per new finding, and post a weekly digest summary.

Text sketch of the data flow:

```
schedule --> check.py --> source of truth (IdP / cloud / HRIS)
                |
                v
         findings JSON --> evidence/ --> git commit
```

Each control is independent. Adding a fourth control means adding one folder and one step in the workflow file.
