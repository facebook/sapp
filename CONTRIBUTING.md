# Contributing to SAPP

We want to make contributing to this project as easy and transparent as possible.

## Pull Requests

We actively welcome your Pull Requests. Please refer to the ["Development Environment Setup"](README.md#development-environment-setup) section to set up the development environment.

In general, the following rules apply to any changes made:

1. If you have added code that should be tested, add tests.
```
sapp/ui/tests/
sapp/pipeline/tests/
sapp/tests/
```
2. If you have changed APIs, update the documentation.
3. If you have not already, complete the Contributor License Agreement ("CLA").

For code changes, the following steps should be taken prior to submitting a Pull Request:

- Run the following linters locally and fix lint errors related to the files you have modified:
  - `black .`
  - `usort format .`
  - `flake8`
- Install all dev dependencies `pip install -r requirements-dev.txt`
- Run tests with `./scripts/run-tests.sh` and make sure all tests are passing

## Contributor License Agreement ("CLA")

To accept your pull request, we need you to submit a CLA. You only need to do this once to work on any of Facebook's open-source projects.

Complete your CLA here: <https://code.facebook.com/cla>. If you have any questions, please drop us a line at <cla@fb.com>.

You are also expected to follow the [Code of Conduct](CODE_OF_CONDUCT.md), so please read that if you are a new contributor.

## Issues

We use [GitHub issues](https://github.com/facebook/sapp/issues) to track public bugs. Please ensure your description is clear and has sufficient instructions to be able to reproduce the issue.

## Coding Style

We value consistent code. Please follow the style of the surrounding code. Useful rules of thumb for all languages are:

- Avoid abbreviations;
- Use auto-formatters to minimize debates about spacing, indentation and line breaks;
- Prefer `snake_case` over `camelCase` for variables and function names;
- Prefer `CamelCase` over `Snake_case` for modules and classes.

## License

By contributing to SAPP, you agree that your contributions will be licensed under the LICENSE file in the root directory of this source tree.
