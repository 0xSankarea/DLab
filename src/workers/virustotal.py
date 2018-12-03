"""virustotal.py: """

__author__ = 'SankaRea'
__email__ = 'sankarea@protonmail.com'

__version__ = '0.1.4'

import urllib3
import json


class VirusTotal(object):
    def __init__(self):
        self.api_key = None

    def get_notification(self):
        try:
            http = urllib3.PoolManager()
            response = http.request('GET','https://www.virustotal.com/intelligence/hunting/notifications-feed/?key={0:s}&output=json'.format(self.api_key))
        except Exception as e:
            print('ERROR#21: Retrieving data from VT, %s' % e)
            return []
        try:
            notifications = response.json()
        except ValueError:
            return []
        return notifications["notifications"]

    def get_files(self, hash):
        try:
            http = urllib3.PoolManager()
            params = {'apikey': self.api_key,
                      'hash': hash}
            response = http.request('GET', 'https://www.virustotal.com/vtapi/v2/file/download', params=params)
            if response.status_code != 200:
                print("Error retrieving the file from VT with status code %s" % response.status_code)
                return None
            data = response.content
            return data
        except Exception as e:
            print("Error#22: Getting files", e)

    def delete_notifications(self, notifications):
        try:
            http = urllib3.PoolManager()
            http.request('POST', 'https://www.virustotal.com/intelligence/hunting/delete-notifications/programmatic/?key={0:s}'.format(
                    self.api_key),data=json.dumps(notifications))
        except Exception as e:
            print("Error#23: Deleting notifications", e)

