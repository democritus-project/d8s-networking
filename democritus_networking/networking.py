import os
import sys
from typing import Any, Dict

import requests

# TODO: I'd like to change `convert_json` to something like `detect_and_convert_response_data`


def _handle_response(
    response,
    url,
    *,
    handle_response_as_bytes: bool = False,
    return_response_object: bool = False,
    convert_json: bool = True,
):
    """Handle the responses from requests."""
    import json

    from json_data import json_read

    # TODO: try to read the input as csv if the content is not json and does not have a lot of angle-brackets in it

    if response.ok:
        if return_response_object:
            return response
        else:
            # TODO: try to convert the content to xml (in addition to the json)
            try:
                return json_read(response.text)
            except json.JSONDecodeError:
                if handle_response_as_bytes:
                    return response.content
                else:
                    return response.text
    else:
        print('{} error from {} {}: {}'.format(response.status_code, response.request.method, url, response.text))
        return response


# TODO: write functions to get and provide a user-agent (and ideally to choose a random user-agent from a list of common ones)


def requests_basic_auth(user, password):
    """Return an instance of request's basic auth."""
    from requests.auth import HTTPBasicAuth

    return HTTPBasicAuth(user, password)


def get(
    url,
    *,
    handle_response_as_bytes: bool = False,
    return_response_object: bool = False,
    convert_json: bool = True,
    process_response: bool = True,
    use_common_user_agent: bool = True,  # TODO: carry this over to the other request functions
    **kwargs,
):
    """Make a GET request to the given URL."""
    from user_agents import user_agent_common

    if use_common_user_agent:
        user_agent = user_agent_common()
        if kwargs.get('headers'):
            if not kwargs['headers'].get('User-Agent'):
                kwargs['headers']['User-Agent'] = user_agent
            # if there is already a user agent provided, use that
        else:
            headers = {'User-Agent': user_agent}
            kwargs['headers'] = headers
    # TODO: follow redirects by default
    response = requests.get(url, **kwargs)
    if process_response:
        result = _handle_response(
            response,
            url,
            handle_response_as_bytes=handle_response_as_bytes,
            return_response_object=return_response_object,
            convert_json=convert_json,
        )
    else:
        result = response

    return result


def head(url, *, process_response=False, **kwargs):
    """Make a head request."""
    response = requests.head(url, **kwargs)

    if process_response:
        return _handle_response(response, url)
    else:
        return response


def post(
    url,
    *,
    update_headers_for_datatype: bool = True,
    handle_response_as_bytes: bool = False,
    convert_json: bool = True,
    return_response_object: bool = False,
    process_response: bool = True,
    **kwargs,
):
    """Make a POST request to the given URL with the given data."""
    import json

    has_data = kwargs.get('data')
    if update_headers_for_datatype and has_data:
        data = kwargs['data']
        # TODO: move this testing elsewhere to detect if the given data is json
        if isinstance(data, (dict, list)):
            kwargs['data'] = json.dumps(data)
            kwargs = _update_header_for_json(**kwargs)

    response = requests.post(url, **kwargs)

    if process_response:
        return _handle_response(
            response,
            url,
            handle_response_as_bytes=handle_response_as_bytes,
            convert_json=convert_json,
            return_response_object=return_response_object,
        )
    else:
        return response


def headers_update(
    headers: Dict[str, str], new_header_key: str, new_header_value: Any, *, overwrite: bool = True
):
    """."""
    if headers.get(new_header_key):
        if overwrite:
            headers[new_header_key] = new_header_value
    else:
        headers[new_header_key] = new_header_value

    return headers


def _update_header_for_json(**kwargs):
    """Given the keyword arguments for a request, check to see if there is already a header, if there is a "Content-Type" header, don't change it; if there is not a "Content-Type" header, add one."""
    if kwargs.get('headers'):
        kwargs['headers'] = headers_update(kwargs['headers'], 'Content-Type', 'application/json', overwrite=False)
    else:
        kwargs['headers'] = {'Content-Type': 'application/json'}

    return kwargs


def put(
    url,
    *,
    update_headers_for_datatype: bool = True,
    handle_response_as_bytes: bool = False,
    convert_json: bool = True,
    return_response_object: bool = False,
    process_response: bool = True,
    **kwargs,
):
    """Make a PUT request to the given URL with the given data."""
    import json

    has_data = kwargs.get('data')
    if update_headers_for_datatype and has_data:
        if isinstance(kwargs['data'], dict) or isinstance(kwargs['data'], list):
            kwargs['data'] = json.dumps(kwargs['data'])
            kwargs = _update_header_for_json(**kwargs)

    response = requests.put(url, **kwargs)

    if process_response:
        return _handle_response(
            response,
            url,
            handle_response_as_bytes=handle_response_as_bytes,
            convert_json=convert_json,
            return_response_object=return_response_object,
        )
    else:
        return response


def delete(
    url,
    *,
    handle_response_as_bytes: bool = False,
    convert_json: bool = True,
    return_response_object: bool = False,
    process_response: bool = True,
    **kwargs,
):
    """Make a DELETE request to the given URL with the given data."""
    response = requests.delete(url, **kwargs)

    if process_response:
        return _handle_response(
            response,
            url,
            handle_response_as_bytes=handle_response_as_bytes,
            convert_json=convert_json,
            return_response_object=return_response_object,
        )
    else:
        return response


def req_redirects(url, *, convert_json: bool = True):
    """Follow the redirects when requesting the given url and return a list of responses."""
    headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-Language": "en-US,en;q=0.9",
        "Connection": "close",
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36",
    }

    response = get(url, headers=headers, return_response_object=True, convert_json=convert_json)
    urls = [entry for entry in response.history]
    # append the most recent response
    urls.append(response)
    return urls


def url_hash(url, hash_type='sha256'):
    """Return the hash of the url."""
    from hashes import _string_hash

    return _string_hash(get(url, convert_json=False), hash_type)


def urllib3_backoff_factor_executions(backoff_factor: float, number_of_requests: int):
    """Return the times (in seconds) of the first n requests with the given backoff_factor. See https://urllib3.readthedocs.io/en/latest/reference/index.html#urllib3.Retry under the "backoff_factor" argument."""
    execution_times = []
    # the end of the range through which we iterate is number_of_requests plus one because we start the iteration at one and we want to have n items in the execution_times array
    range_end = number_of_requests + 1

    for i in range(1, range_end):
        # if the original request (which can be considered the zeroth request) fails, the first re-request is made immediately by urllib3
        if i == 1:
            execution_times = [0.0]
        else:
            # TODO: is there an easier way to do this?
            function_string = f'{backoff_factor} * (2 ** ({i} - 1))'
            new_execution_time = eval(function_string)
            execution_times.append(new_execution_time)

    return execution_times
