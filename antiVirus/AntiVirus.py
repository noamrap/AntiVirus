import os
import requests
from time import sleep
import sys

class VirusTotalAPI:
    def __init__(self, api_key):
        self.api_key = api_key

    def upload_file(self, file_path):
        url = 'https://www.virustotal.com/vtapi/v2/file/scan'
        with open(file_path, 'rb') as file:
            files = {'file': file}
            params = {'apikey': self.api_key}
            response = requests.post(url, data=params, files=files)
            response.raise_for_status()

            if response.headers['Content-Type'] == 'application/json':
                return response.json()['resource']
            else:
                raise Exception('Unable to locate result')

    def retrieve_report(self, resource_id):
        url = 'https://www.virustotal.com/vtapi/v2/file/report'
        params = {'apikey': self.api_key, 'resource': resource_id}
        while True:
            response = requests.get(url, params=params)
            response.raise_for_status()

            if response.headers['Content-Type'] == 'application/json':
                result = response.json()
                if result['response_code'] == 1:
                    break
                else:
                    delay = 25
                    sleep(delay)
            else:
                raise Exception('Invalid content type')

        report = result
        positives = [engine for engine, result in report['scans'].items() if result['detected']]
        return positives

def get_file_path():
    return input('Enter a file path: ')

def check_if_path_exists(file_path):
    if os.path.exists(file_path):
        print('The file exists')
        return True
    else:
        print('The specified file does NOT exist')
        sys.exit(1)

def main():
    api_key = '7ca5a5e66b464c669f68a8a795a83d1bc59ff75d2d4eb6c1add7418dcbfa1fd3'
    file_path = get_file_path()
    if check_if_path_exists(file_path):
        api = VirusTotalAPI(api_key)
        resource_id = api.upload_file(file_path)
        positives = api.retrieve_report(resource_id)

        print(f'Scanned file: {file_path}')
        print(f'Positives: {len(positives)}')

        if positives:
            print(f'WARNING: Found {len(positives)} alerts. Please see the full report above.')
            sys.exit(1)
        else:
            print('No positives found. The file appears to be safe.')
            sys.exit(0)

if __name__ == '__main__':
    main()
