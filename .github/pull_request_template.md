## What this changes

<!-- One or two sentences. What behaviour is different after this PR? -->

## Why

<!-- The problem. Link an issue if there is one: Fixes #123 -->

## How it was verified

<!-- Which suites you ran, and on which OS. If you added a test, name it. -->

- [ ] All seven suites pass (`test_p0 test_e2e test_live test_vpn test_raw test_sudokey test_ui`)
- [ ] New behaviour has a test that fails without the change
- [ ] No new runtime dependency, or the PR explains why stdlib could not do it
- [ ] No secret written outside the encrypted vault, and nothing bound off `127.0.0.1`

<!-- See CONTRIBUTING.md. PRs to main only; direct pushes are blocked. -->
