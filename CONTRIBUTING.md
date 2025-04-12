# Contributing to Account Selector

Thank you for considering contributing to Account Selector. This document provides guidelines to help you contribute effectively to the project.

## Code of Conduct

All contributors are expected to adhere to professional standards of conduct:

- Be respectful and considerate of others
- Provide constructive feedback
- Focus on the issue at hand rather than personal disagreements
- Support an inclusive and collaborative environment

## How to Contribute

### Reporting Bugs

When reporting bugs, please create an issue with the following information:

- A clear, descriptive title
- A detailed description of the issue
- Steps to reproduce the bug
- Expected and actual behavior
- Screenshots if applicable
- Your environment details (OS, Python version, etc.)

### Suggesting Enhancements

For feature requests, please create an issue with:

- A clear, descriptive title
- A detailed description of the proposed feature
- Any relevant examples or mock-ups
- Potential use cases for the feature
- How the feature would benefit the project

### Pull Requests

Follow these steps to submit a pull request:

1. Fork the repository
2. Create a new branch (`git checkout -b feature/your-feature`)
3. Make your changes
4. Add tests for new features or bug fixes
5. Ensure all tests pass by running `python -m pytest` in the root directory
6. Update documentation if necessary
7. Commit your changes (`git commit -m 'Add some feature'`)
8. Push to the branch (`git push origin feature/your-feature`)
9. Create a Pull Request

## Development Setup

1. Clone the repository
   ```bash
   git clone https://github.com/Mahdiglm/AccountSelector.git
   cd AccountSelector
   ```
2. Install dependencies
   ```bash
   pip install -r requirements.txt
   ```
3. Run the application
   ```bash
   python account_selector.py
   ```
4. Run tests
   ```bash
   python -m pytest
   ```

## Coding Guidelines

### Style

- Follow [PEP 8](https://www.python.org/dev/peps/pep-0008/) style guidelines
- Use consistent indentation (4 spaces)
- Keep line length under 100 characters
- Use meaningful variable and function names

### Documentation

- Document all functions, classes, and modules using docstrings
- Keep comments up-to-date with code changes
- Add README updates for significant new features

### Testing

- Write unit tests for new functionality
- Ensure existing tests pass with your changes
- Aim for high test coverage of critical functionality

### Commit Messages

- Use clear, descriptive commit messages
- Begin with a short summary line (50 chars or less)
- Reference issue numbers when applicable
- Example: "Fix login validation issue (#123)"

## Release Process

1. Version numbers follow [Semantic Versioning](https://semver.org/)
2. Update CHANGELOG.md with changes
3. Update version numbers in relevant files
4. Create a GitHub release with release notes

## License

By contributing to Account Selector, you agree that your contributions will be licensed under the project's [MIT License](LICENSE).
