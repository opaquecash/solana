<!-- Describe the change. Keep program changes small and reviewable. -->

## Anchor account-constraints review (required for program changes)

Check each item or mark N/A. This is the Phase 3.3 pre-audit checklist; a reviewer
must be able to verify every box from the diff.

- [ ] Every `Account`/`UncheckedAccount` that must be program-owned is constrained
      (`owner =`, typed `Account<'info, T>`, or an explicit handler check)
- [ ] PDAs verify their full seed set and bump (`seeds = [...]`, `bump`), and
      cross-program PDAs pin `seeds::program`
- [ ] Authority/admin accounts are `Signer` and tied to stored state
      (`has_one =` / explicit key comparison), not just any signer
- [ ] `init` accounts cannot be replayed (init-once semantics intended) and `init_if_needed`
      is justified in a comment if used
- [ ] Mutability is minimal: `#[account(mut)]` only where lamports/data actually change
- [ ] CPI targets are pinned (`address =` constraint or checked program id), never taken
      from unvalidated instruction input
- [ ] Arithmetic on lamports/amounts uses checked ops or is bounds-justified
- [ ] New instructions emit events for state changes scanners/indexers rely on
- [ ] `cargo clippy --all-targets` is clean and integration tests cover the happy path
      plus at least one constraint-violation rejection per new instruction
