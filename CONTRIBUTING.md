# Contributing Guide

We love your input! We want to make contributing to Human Network Pre SDK as easy and transparent as possible, whether it's:

- Reporting a bug
- Discussing the current state of the code
- Submitting a fix
- Proposing new features

## We Develop with GitHub

We use GitHub to host code, to track issues and feature requests, as well as accept pull requests.

## Development Process

1. Fork the repo and create your branch from `main`
2. If you've added code that should be tested, add tests
3. If you've changed APIs, update the documentation
4. Ensure the test suite passes
5. Make sure your code lints
6. Issue that pull request!

## Pull Request Process

1. Update the README.md with details of changes to the interface, if applicable
2. Update the documentation with any new API changes
3. The PR will be merged once you have the sign-off of at least one maintainer

## Any contributions you make will be under the MIT Software License

In short, when you submit code changes, your submissions are understood to be under the same [MIT License](LICENSE.md) that covers the project. Feel free to contact the maintainers if that's a concern.

## Report bugs using Github's [issue tracker](https://github.com/tuantran-genetica/human-network-pre-lib/issues)

We use GitHub issues to track public bugs. Report a bug by [opening a new issue](https://github.com/tuantran-genetica/human-network-pre-lib/issues/new).

## Write bug reports with detail, background, and sample code

**Great Bug Reports** tend to have:

- A quick summary and/or background
- Steps to reproduce
  - Be specific!
  - Give sample code if you can
- What you expected would happen
- What actually happens
- Notes (possibly including why you think this might be happening, or stuff you tried that didn't work)

## Development Setup

```bash
# Install dependencies
pnpm install

# Run tests
pnpm test

# Build the project
pnpm run build

# Run linter
pnpm run lint
```

## Testing

We use Jest for testing. Please ensure all new features include appropriate tests:

```bash
# Run all tests
pnpm test

# Run tests in watch mode
pnpm test -- --watch

# Run tests with coverage
pnpm test -- --coverage
```

## Code Style

- We use TypeScript for type safety
- Follow the existing code style
- Use meaningful variable names
- Add comments for complex logic
- Keep functions small and focused

## Documentation

- Keep README.md up to date
- Document all public APIs
- Include JSDoc comments for TypeScript interfaces and functions
- Update documentation when changing functionality

## License

By contributing, you agree that your contributions will be licensed under its (MIT License)[LICENSE.md].
