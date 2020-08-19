import requests
from requests.auth import HTTPBasicAuth
from requests.exceptions import HTTPError
import os
import json


def get_api_token(username, password):
    url = 'https://sas.cwp.radwarecloud.com/sas/login'
    payload = {"username": username, "password": password}

    api_session = http_request(request_type='post', url=url, payload=payload, token=None, silent=False)
    api_session = json.loads(api_session.content)

    return api_session['token']


def http_request(request_type, url, payload, token, silent):
    # request_type = post/delete/get
    request_type = request_type.lower()
    # silent = True/False

    if token:
        headers = {'Content-Type': 'application/json',
                   'Authorization': f'BEARER {token}'}
    else:
        print("INFO: No API token tendered for HTTP request.")
        headers = {'Content-Type': 'application/json'}

    resp = ''
    try:
        if request_type.lower() == 'post':
            resp = requests.post(url, json=payload, headers=headers)
        elif request_type.lower() == 'delete':
            resp = requests.delete(url, json=payload, headers=headers)
        elif request_type.lower() == 'get':
            resp = requests.get(url, json=payload, headers=headers)
        else:
            print('Request type not supported.')
            return False

        resp.raise_for_status()
    except HTTPError as http_err:
        print(f'HTTP error occurred: {http_err}')
    except Exception as err:
        print(f'Other error occurred: {err}')
    else:
        if not silent:
            print('Success!')

    return resp


def main():
    token = get_api_token(username='api_user@radwarese.com', password='Matt!234')
    print(f"My Token: {token}")

    url = 'https://api.us-east-1.cwp.radwarecloud.com/api/v1/warning/334160335986'
    warning = http_request(request_type='get', url=url, payload=None, token=token, silent=False)
    print(warning.content)


if __name__ == '__main__':
    main()
