# Contributing to SPARTAN

Thank you for your interest in contributing. SPARTAN is a security research
tool — all contributions must uphold the project's ethical standards.

---

## Before You Start

- Read the [Ethical & Legal Notice](README.md#ethical--legal-notice) in the
  README.
- All contributions must be intended for **authorized security research only**.
- Do not contribute payloads, exploits, or techniques designed to harm
  real systems without authorization.

---

## How to Contribute

### Bug Reports

Use the [bug report template](.github/ISSUE_TEMPLATE/bug_report.md). Include:

- Python version and OS
- Full error traceback
- Minimal reproduction steps
- What you expected vs. what happened

### Feature Requests

Use the [feature request template](.github/ISSUE_TEMPLATE/feature_request.md).
Clearly describe the use case and why it benefits authorized security research.

### Pull Requests

1. **Fork** the repository and create a branch from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Write tests** for any new functionality. The test suite lives in `tests/`
   and uses `pytest`. All 244 existing tests must continue to pass:
   ```bash
   python -m pytest tests/ -v
   ```

3. **Follow the code style** — PEP 8, type hints on public functions, and
   docstrings on new modules/classes.

4. **Update documentation** — update `README.md` and inline docs if your
   change adds or modifies any user-facing behaviour.

5. **Open a pull request** using the [PR template](.github/PULL_REQUEST_TEMPLATE.md).

---

## Development Setup

```bash
# Clone and create a virtual environment
git clone https://github.com/Reinasboo/SPARTAN.git
cd SPARTAN
python -m venv .venv

# Windows
.venv\Scripts\activate

# macOS/Linux
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
pip install pytest

# Run tests
python -m pytest tests/ -v
```

---

## Project Structure

See the [Project Structure](README.md#project-structure) section of the README
for a full map of the codebase.

---

## Code of Conduct

Be respectful. Harassment, hate speech, or contributions intended to harm
individuals or systems are grounds for immediate ban.
