# Contributing to AgentGuard

First off, thank you for considering contributing to AgentGuard! 🎉

Our mission is to make autonomous AI agents safe and predictable without introducing heavyweight dependencies or complicated setups.

---

## Code of Conduct

We are committed to providing a welcoming, inspiring, and harassment-free community for everyone. Be respectful, constructive, and kind in all interactions.

---

## How Can I Contribute?

### 1. Reporting Bugs
- Search existing issues to ensure the bug hasn't already been reported.
- Use our [Bug Report Template](.github/ISSUE_TEMPLATE/bug_report.yml).
- Include the exact command, your OS, Python version, and minimal reproduction steps.

### 2. Proposing Security Rules & Features
- Open a feature request detailing the attack vector or enhancement.
- Explain real-world scenarios where autonomous agents fail or cause damage.

### 3. Submitting Pull Requests
1. Fork the repo and create your branch from `main`:
   ```bash
   git checkout -b feature/my-new-threat-rule
   ```
2. Set up your local development environment:
   ```bash
   pip install -e .
   ```
3. Add unit tests for your changes under `tests/`.
4. Run all tests to ensure zero regressions:
   ```bash
   python -m unittest discover tests
   ```
5. Ensure commit messages are descriptive and follow conventional commits (e.g., `feat: add docker escape detection rule`).
6. Push your branch and open a Pull Request!

---

## Testing Guidelines

- Every new rule or security heuristic must include:
  - At least 1 test verifying it blocks the hostile pattern.
  - At least 1 test verifying it does not trigger a false positive on benign developer commands.

---

## Questions?

Open a discussion or issue on GitHub. We love helping developers get their first PR merged!
