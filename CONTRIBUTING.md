# Contributing to NOA SQL Scanner

First off, thank you for considering contributing to NOA SQL Scanner! 🎉

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
- [Development Setup](#development-setup)
- [Coding Standards](#coding-standards)
- [Commit Guidelines](#commit-guidelines)
- [Pull Request Process](#pull-request-process)

## 📜 Code of Conduct

This project adheres to a code of conduct. By participating, you are expected to uphold this code:

- Be respectful and inclusive
- Welcome newcomers and encourage diversity
- Focus on what is best for the community
- Show empathy towards other community members

## 🤝 How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check existing issues. When creating a bug report, include:

- **Clear title and description**
- **Steps to reproduce**
- **Expected vs actual behavior**
- **Environment details** (OS, Python version, etc.)
- **Screenshots** if applicable

**Bug Report Template:**
```markdown
## Description
Brief description of the bug

## Steps to Reproduce
1. Run command `...`
2. Scan URL `...`
3. Observe error

## Expected Behavior
What should happen

## Actual Behavior
What actually happened

## Environment
- OS: Ubuntu 22.04
- Python: 3.10.5
- SQL Scanner: 1.0.0
```

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. Provide:

- **Clear title and description**
- **Use case** - why is this enhancement needed?
- **Proposed solution**
- **Alternative solutions** considered

### Pull Requests

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Make your changes
4. Write/update tests
5. Ensure tests pass
6. Commit with clear messages
7. Push to your fork
8. Open a Pull Request

## 🛠️ Development Setup

### Prerequisites

- Python 3.8+
- pip
- git

### Setup Steps

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/sql-scanner.git
cd sql-scanner

# Add upstream remote
git remote add upstream https://github.com/ORIGINAL_OWNER/sql-scanner.git

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install development dependencies
pip install pytest pytest-cov flake8 black isort

# Install in development mode
pip install -e .
```

### Running Tests

```bash
# Run all tests
pytest tests/

# Run with coverage
pytest --cov=. tests/

# Run specific test file
pytest tests/test_detector.py

# Run with verbose output
pytest -v tests/
```

### Code Quality Checks

```bash
# Format code with Black
black .

# Sort imports with isort
isort .

# Lint with flake8
flake8 .

# Type checking (if using mypy)
mypy .
```

## 📝 Coding Standards

### Python Style Guide

We follow [PEP 8](https://www.python.org/dev/peps/pep-0008/) with these specifics:

- **Line length**: 100 characters (not 79)
- **Indentation**: 4 spaces
- **Quotes**: Single quotes for strings, double for docstrings
- **Naming**:
  - Classes: `PascalCase`
  - Functions/variables: `snake_case`
  - Constants: `UPPER_CASE`

### Code Example

```python
"""
Module docstring describing the module purpose
"""

import sys
from typing import List, Optional

from .config import MAX_URLS

class MyScanner:
    """Class docstring describing the class"""
    
    def __init__(self, target: str):
        """Initialize scanner with target URL"""
        self.target = target
        self.results: List[dict] = []
    
    def scan(self, url: str) -> Optional[dict]:
        """
        Scan a single URL
        
        Args:
            url: The URL to scan
            
        Returns:
            Dictionary with results or None if failed
        """
        # Implementation here
        pass
```

### Documentation

- **Docstrings**: Use Google-style docstrings
- **Comments**: Explain *why*, not *what*
- **Type hints**: Use where appropriate
- **README**: Update if adding features

### Testing

- Write tests for new features
- Maintain >80% code coverage
- Test both success and failure cases
- Use descriptive test names

```python
def test_mysql_error_detection_with_single_quote():
    """Test that MySQL errors are detected with single quote payload"""
    # Arrange
    detector = VulnerabilityDetector()
    response_text = "SQL syntax error near '1'='1'"
    
    # Act
    vulnerable, db_type, _, _ = detector.detect_error_based(
        response_text, "' OR '1'='1"
    )
    
    # Assert
    assert vulnerable is True
    assert db_type == 'MySQL'
```

## 📝 Commit Guidelines

### Commit Message Format

```
<type>(<scope>): <subject>

<body>

<footer>
```

### Types

- **feat**: New feature
- **fix**: Bug fix
- **docs**: Documentation changes
- **style**: Code style changes (formatting, etc.)
- **refactor**: Code refactoring
- **test**: Adding/updating tests
- **chore**: Maintenance tasks

### Examples

```bash
feat(scanner): add POST parameter testing support

- Implement POST request handling
- Add form data injection
- Update tests for POST methods

Closes #42

---

fix(crawler): handle SSL certificate errors gracefully

Previously, the crawler would crash on SSL errors.
Now it catches the exception and continues.

Fixes #38

---

docs(readme): update installation instructions

Added troubleshooting section for common install issues
```

### Commit Best Practices

- Use present tense ("add feature" not "added feature")
- Keep subject line under 50 characters
- Capitalize subject line
- No period at end of subject
- Separate subject from body with blank line
- Wrap body at 72 characters
- Explain *what* and *why*, not *how*

## 🔄 Pull Request Process

### Before Submitting

✅ **Checklist:**

- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Comments added for complex code
- [ ] Documentation updated
- [ ] Tests added/updated
- [ ] All tests passing
- [ ] No new warnings
- [ ] Commit messages follow guidelines

### PR Description Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
Describe tests performed:
- [ ] Unit tests added
- [ ] Integration tests added
- [ ] Manual testing completed

## Screenshots (if applicable)
Add screenshots to demonstrate changes

## Related Issues
Fixes #(issue number)

## Checklist
- [ ] Code follows project style
- [ ] Self-review completed
- [ ] Tests added
- [ ] Documentation updated
- [ ] All tests passing
```

### Review Process

1. **Automated checks** must pass (CI/CD)
2. **Code review** by at least one maintainer
3. **Testing** - reviewer may test changes
4. **Approval** - PR approved by maintainer
5. **Merge** - maintainer merges PR

### After PR is Merged

- Delete your feature branch
- Pull latest changes from upstream
- Update your fork

```bash
git checkout main
git pull upstream main
git push origin main
```

## 🎯 Areas for Contribution

### High Priority

- [ ] Multi-threading implementation
- [ ] POST parameter testing
- [ ] JSON/HTML report formats
- [ ] Improved WAF bypass techniques
- [ ] Better error handling

### Medium Priority

- [ ] Cookie injection testing
- [ ] Header injection testing
- [ ] MongoDB/NoSQL support
- [ ] Proxy support
- [ ] Authentication support

### Good First Issues

- [ ] Improve documentation
- [ ] Add more test cases
- [ ] Enhance error messages
- [ ] Add more SQL payloads
- [ ] Fix typos/formatting

### Documentation Improvements

- [ ] Video tutorials
- [ ] More usage examples
- [ ] Troubleshooting guide
- [ ] Performance optimization tips
- [ ] Security best practices

## 🐛 Debugging Tips

### Enable Debug Mode

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

### Common Issues

**Issue: Import errors**
```bash
# Solution: Install in development mode
pip install -e .
```

**Issue: Tests failing**
```bash
# Solution: Update dependencies
pip install --upgrade -r requirements.txt
```

**Issue: SSL certificate errors**
```bash
# Solution: Set verify=False (testing only!)
# Already handled in code
```

## 📚 Resources

### Learning Resources

- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [Python Best Practices](https://docs.python-guide.org/)
- [Git Best Practices](https://git-scm.com/book/en/v2)
- [Pytest Documentation](https://docs.pytest.org/)

### Similar Projects

- [SQLMap](https://github.com/sqlmapproject/sqlmap)
- [NoSQLMap](https://github.com/codingo/NoSQLMap)
- [Commix](https://github.com/commixproject/commix)

## 💬 Communication

### Where to Ask Questions

- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: General questions and ideas
- **Pull Requests**: Code-specific discussions

### Getting Help

If you're stuck:

1. Check existing issues and documentation
2. Search closed issues and PRs
3. Ask in GitHub Discussions
4. Provide detailed context and code samples

## 🙏 Recognition

Contributors will be:

- Listed in README acknowledgments
- Mentioned in release notes
- Credited in commit history

Thank you for contributing! 🚀

## 📄 License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

**Questions?** Feel free to open an issue or discussion!
