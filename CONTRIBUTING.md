# Contributing to NeuroCipher

Thank you for your interest in contributing to NeuroCipher! We welcome contributions from the community to help make cybersecurity accessible to small and medium businesses.

## Code of Conduct

We are committed to providing a welcoming and inclusive environment for all contributors. Please be respectful and professional in all interactions.

## How to Contribute

### 🐛 Reporting Bugs

1. Check if the issue already exists in our [Issues](https://github.com/chipster6/neurocipher-platform/issues)
2. Create a new issue with:
   - Clear description of the problem
   - Steps to reproduce
   - Expected vs actual behavior
   - System information (OS, Python version, etc.)

### 💡 Suggesting Features

1. Check existing [Feature Requests](https://github.com/chipster6/neurocipher-platform/issues?q=is%3Aissue+label%3Aenhancement)
2. Create a new issue with:
   - Clear description of the feature
   - Use case and business value
   - Proposed implementation approach

### 🔧 Development Setup

```bash
# Clone the repository
git clone https://github.com/chipster6/neurocipher-platform.git
cd neurocipher-platform

# Create virtual environment
python3 -m venv neurocipher_env
source neurocipher_env/bin/activate

# Install dependencies
pip install -r requirements.txt

# Set up environment
cp .env.template .env
# Edit .env with your configuration

# Run tests
pytest tests/

# Start development server
python run_unified_dashboard.py
```

### 📝 Pull Request Process

1. **Fork** the repository
2. **Create** a feature branch: `git checkout -b feature/amazing-feature`
3. **Make** your changes following our coding standards
4. **Add** tests for new functionality
5. **Run** the test suite: `pytest`
6. **Update** documentation as needed
7. **Commit** with descriptive messages
8. **Push** to your fork: `git push origin feature/amazing-feature`
9. **Create** a Pull Request

### 🧪 Testing Guidelines

- Write tests for all new features
- Maintain test coverage above 95%
- Include both unit and integration tests
- Test edge cases and error conditions

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src tests/

# Run specific test categories
pytest tests/unit/
pytest tests/integration/
pytest tests/security/
```

## 📋 Development Standards

### Code Style

- Follow PEP 8 for Python code
- Use type hints for all function signatures
- Write descriptive docstrings for all modules, classes, and functions
- Keep functions small and focused (max 50 lines)

### Commit Messages

Use conventional commit format:

```
type(scope): description

Examples:
feat(ai): add GPU auto-detection for inference
fix(api): resolve authentication token validation
docs(readme): update installation instructions
test(security): add comprehensive auth tests
```

### Documentation

- Update README.md for user-facing changes
- Add docstrings for all new code
- Include code examples for new features
- Update API documentation as needed

## 🏗️ Architecture Guidelines

### Core Principles

1. **SMB-First Design**: All features must be accessible to non-technical users
2. **Plain English**: Security findings must be explained in business terms
3. **One-Click Solutions**: Complex operations should be automated
4. **Privacy-First**: Customer data never leaves their infrastructure
5. **Performance**: Sub-2-minute SLA for all security operations

### Component Guidelines

- **AI Analytics**: Use GPU when available, fallback to CPU
- **Vector Search**: Semantic search for threat correlation
- **API Design**: RESTful with comprehensive error handling
- **Security**: End-to-end encryption with post-quantum readiness
- **Multi-Tenant**: Strict data isolation between customers

## 🔒 Security Considerations

- Never commit API keys or sensitive data
- Use environment variables for all configuration
- Follow secure coding practices (OWASP guidelines)
- Implement proper input validation and sanitization
- Add security tests for all authentication/authorization code

## 📊 Performance Requirements

- API responses: <200ms average
- Security scans: <2 minutes end-to-end
- UI interactions: <100ms response time
- Memory usage: <2GB under normal load
- Test coverage: >95% for all components

## 🤝 Community

### Getting Help

- **Discord**: [Join our community](https://discord.gg/neurocipher)
- **GitHub Discussions**: For questions and ideas
- **Email**: developers@neurocipher.io

### Recognition

Contributors will be:
- Listed in our CONTRIBUTORS.md file
- Mentioned in release notes
- Eligible for NeuroCipher swag
- Invited to exclusive contributor events

## 📄 License

By contributing to NeuroCipher, you agree that your contributions will be licensed under the same license as the project.

---

**Thank you for helping make cybersecurity accessible to everyone!** 🧠⚡