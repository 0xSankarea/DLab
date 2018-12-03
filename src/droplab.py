"""droplab.py: """

__author__ = 'SankaRea'
__email__ = 'sankarea@protonmail.com'

__version__ = '0.1.4'

import urllib3
import configparser
import datetime
import time
from workers import virustotal, elastic, cuckoo

CONFIG_FILE_PATH = '../config/main.cfg'


class DROPLab(object):
    def __init__(self):
        self.vt_worker = virustotal.VirusTotal()
        self.cuckoo_worker = cuckoo.Cuckoo()
        self.elastic_worker = elastic.Elastic()
        self.import_config(CONFIG_FILE_PATH)

    def import_config(self,config_path = None):
        if config_path is None:
            print('ERROR#11: Config file path is not specified.')
            exit(11)
        else:
            config = configparser.RawConfigParser()
            config.read(config_path)
        try:
            # VirusTotal
            self.vt_worker.api_key = config.get('VirusTotal', 'API_KEY')
            # Elastic
            self.elastic_worker.URL = config.get('Elastic', 'URL')
            self.elastic_worker.index = config.get('Elastic', 'INDEX')
            self.elastic_worker.login = config.get('Elastic', 'LOGIN')
            self.elastic_worker.password = config.get('Elastic', 'PASSWORD')
            # Cuckoo
            self.cuckoo_worker.url = config.get('Cuckoo', 'URL')
            self.cuckoo_worker.instans = config.get('Cuckoo', 'INSTATS')
            self.cuckoo_worker.login = config.get('Cuckoo', 'LOGIN')
            self.cuckoo_worker.password = config.get('Cuckoo', 'PASSWORD')
        except configparser.NoOptionError:
            print('ERROR#12: Parameters not found')
            exit(12)

    @staticmethod
    def convert_date(datestring):
        fmt = "%Y-%m-%d %H:%M:%S"
        t = datetime.datetime.strptime(datestring, fmt)
        epochms = time.mktime(t.timetuple()) * 1000
        return int(epochms)

    def processing(self, notification):
        # SUBMIT to Cuckoo
        data = self.vt_worker.get_files(notification['md5'])  # this uses the same VT API key to download *THIS USES DOWNLOADS*
        files = {'file': (notification["subject"], data)}
        params = {'tags': notification["subject"],
                    "options": "route=none",
                    "machine": self.cuckoo_worker.instans,
                    "platform": "windows",
                    "priority": 2,
                    "timeout": 300,
                    "custom": notification["subject"]}
        print('Submitted notification %s with hash %s to Cuckoo' % (notification["subject"], notification["md5"]))
        cuckoo_url = "%s/tasks/create/file" % self.cuckoo_worker.url
        http = urllib3.PoolManager()
        if self.cuckoo_worker.login is not None and self.cuckoo_worker.password is not None:
            response = http.request('POST', cuckoo_url, files=files, data=params, auth=(self.cuckoo_worker.login, self.cuckoo_worker.password))
        else:
            response = http.request('POST', cuckoo_url, files=files, data=params)
        try:
            task_id = response.json()["task_id"]
            print('Submitted %s to cuckoo received task id %s' % (notification["md5"], task_id))
        except Exception as e:
            print("ERROR#22: Submit %s to cuckoo with exception %s" % (notification["md5"], e))

    def indexing(self):
        bulk = []
        notifications = self.vt_worker.get_notification()

        if len(notifications) == 0:
            print('No new notification')
            return

        ids_to_delete = []
        # get the notifications ready for insert
        for notification in notifications:
            id = notification["id"]
            ids_to_delete.append(id)
            notification.pop("id", None)
            if "first_seen" in notification:
                notification["first_seen"] = self.convert_date(notification["first_seen"])
            if "last_seen" in notification:
                notification["last_seen"] = self.convert_date(notification["last_seen"])
            notification["date"] = self.convert_date(notification["date"])
            print(notification)

            # send the notification to be post processed
            self.processing(notification)
            request = {
                "_index": self.elastic_worker.index,
                "_type": "notification",
                "_id": id,
                "_source": notification
            }

            bulk.append(request)
            try:
                self.elastic_worker.bulk(bulk)
                self.vt_worker.delete_notifications(ids_to_delete)
                print("Inserted %s notifications successfully" % len(bulk))
            except Exception as e:
                self.elastic_worker.get_connection()
                print("Error inserting data into ES; reestablished connection %s" % e)


if __name__ == '__main__':
    agent = DROPLab()
    while True:
        agent.indexing()
        time.sleep(300)

