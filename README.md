# Democritus Networking

[![PyPI](https://img.shields.io/pypi/v/d8s-networking.svg)](https://pypi.python.org/pypi/d8s-networking)
[![CI](https://github.com/democritus-project/d8s-networking/workflows/CI/badge.svg)](https://github.com/democritus-project/d8s-networking/actions)
[![Lint](https://github.com/democritus-project/d8s-networking/workflows/Lint/badge.svg)](https://github.com/democritus-project/d8s-networking/actions)
[![codecov](https://codecov.io/gh/democritus-project/d8s-networking/branch/main/graph/badge.svg?token=V0WOIXRGMM)](https://codecov.io/gh/democritus-project/d8s-networking)
[![The Democritus Project uses semver version 2.0.0](https://img.shields.io/badge/-semver%20v2.0.0-22bfda)](https://semver.org/spec/v2.0.0.html)
[![The Democritus Project uses black to format code](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![License: LGPL v3](https://img.shields.io/badge/License-LGPL%20v3-blue.svg)](https://choosealicense.com/licenses/lgpl-3.0/)

Democritus functions<sup>[1]</sup> for working with network requests.

[1] Democritus functions are <i>simple, effective, modular, well-tested, and well-documented</i> Python functions.

We use `d8s` (pronounced "dee-eights") as an abbreviation for `democritus` (you can read more about this [here](https://github.com/democritus-project/roadmap#what-is-d8s)).

## Functions

  - ```python
    def requests_basic_auth(user, password):
        """Return an instance of request's basic auth."""
    ```
  - ```python
    def get(
        url,
        *,
        use_common_user_agent: bool = True,
        process_response: bool = False,
        process_response_as_bytes: bool = False,
        **request_kwargs,
    ):
        """Make a GET request to the given URL."""
    ```
  - ```python
    def head(url, *, process_response: bool = False, **kwargs):
        """Make a head request."""
    ```
  - ```python
    def post(
        url,
        *,
        update_headers_for_datatype: bool = True,
        process_response: bool = False,
        process_response_as_bytes: bool = False,
        **request_kwargs,
    ):
        """Make a POST request to the given URL with the given data."""
    ```
  - ```python
    def headers_update(headers: Dict[str, str], new_header_key: str, new_header_value: Any, *, overwrite: bool = True):
        """."""
    ```
  - ```python
    def put(
        url,
        *,
        update_headers_for_datatype: bool = True,
        process_response: bool = False,
        process_response_as_bytes: bool = False,
        **request_kwargs,
    ):
        """Make a PUT request to the given URL with the given data."""
    ```
  - ```python
    def delete(
        url,
        *,
        process_response: bool = False,
        process_response_as_bytes: bool = False,
        **request_kwargs,
    ):
        """Make a DELETE request to the given URL with the given data."""
    ```
  - ```python
    def url_hash(url, hash_type='sha256'):
        """Return the hash of the url."""
    ```
  - ```python
    def urllib3_backoff_factor_executions(backoff_factor: float, number_of_requests: int):
        """Return the times (in seconds) of the first n requests with the given backoff_factor. See https://urllib3.readthedocs.io/en/latest/reference/index.html#urllib3.Retry under the "backoff_factor" argument."""
    ```

## Development

👋 &nbsp;If you want to get involved in this project, we have some short, helpful guides below:

- [contribute to this project 🥇][contributing]
- [test it 🧪][local-dev]
- [lint it 🧹][local-dev]
- [explore it 🔭][local-dev]

If you have any questions or there is anything we did not cover, please raise an issue and we'll be happy to help.

## Credits

This package was created with [Cookiecutter](https://github.com/audreyr/cookiecutter) and Floyd Hightower's [Python project template](https://github.com/fhightower-templates/python-project-template).

[contributing]: https://github.com/democritus-project/.github/blob/main/CONTRIBUTING.md#contributing-a-pr-
[local-dev]: https://github.com/democritus-project/.github/blob/main/CONTRIBUTING.md#local-development-
