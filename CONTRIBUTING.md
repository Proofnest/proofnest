# Contributing to ProofNest

Thank you for your interest in contributing to ProofNest! This document provides guidelines for contributing.

## Code of Conduct

Be respectful, inclusive, and professional. We're building trust infrastructure - let's build trust in our community too.

## How to Contribute

### Reporting Bugs

1. Check existing issues first
2. Create a new issue with:
   - Clear title
   - Steps to reproduce
   - Expected vs actual behavior
   - Python version and OS
   - ProofNest version (`pip show proofnest`)

### Suggesting Features

1. Check existing issues/discussions
2. Open a feature request issue
3. Describe the use case and proposed solution

### Submitting Code

1. **Fork** the repository
2. **Create a branch**: `git checkout -b feature/my-feature`
3. **Make changes** following our style guide
4. **Test** your changes
5. **Commit** with clear messages
6. **Push** and create a Pull Request

## Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/proofnest.git
cd proofnest

# Create virtual environment
python -m venv venv
source venv/bin/activate  # or `venv\Scripts\activate` on Windows

# Install in development mode
pip install -e ".[dev]"

# Run tests
pytest

# Run linting
black proofnest
mypy proofnest
```

## Style Guide

- **Python**: Follow PEP 8, use Black formatter
- **Type hints**: Required for all public functions
- **Docstrings**: Google style for all public APIs
- **Tests**: Required for new features and bug fixes

### Commit Messages

Use clear, descriptive commit messages:

```
feat: add Bitcoin OP_RETURN anchoring
fix: resolve path traversal in storage
docs: update API reference
test: add chain verification tests
```

## Pull Request Process

1. Update README.md if needed
2. Add tests for new functionality
3. Ensure all tests pass
4. Update CHANGELOG.md
5. Request review from maintainers

### PR Checklist

- [ ] Tests pass locally
- [ ] Code follows style guide
- [ ] Documentation updated
- [ ] CHANGELOG.md updated
- [ ] No security vulnerabilities introduced

## Areas for Contribution

### High Priority
- Test coverage improvements
- Documentation and examples
- Performance optimizations
- Security hardening

### Good First Issues
- Look for issues labeled `good first issue`
- Documentation improvements
- Test additions
- Example code

## Questions?

- Open a GitHub Discussion
- Email: admin@stellanium.io

## License

By contributing, you agree that your contributions will be licensed under the Apache 2.0 License.

---

Thank you for helping make AI decisions verifiable!
