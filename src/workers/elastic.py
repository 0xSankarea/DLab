"""droplab.py: """

__author__ = 'SankaRea'
__email__ = 'sankarea@protonmail.com'

__version__ = '0.1.4'

import json
from elasticsearch import Elasticsearch, helpers


class Elastic(object):
    def __init__(self):
        self.login = None
        self.password = None
        self.index = None
        self.URL = None
        self.conn = None

        def push_mappings(self):
            mapping = {
                "mappings": {
                    "notification": {
                        "properties": {
                            "date": {"type": "date", "doc_values": True},
                            "first_seen": {"type": "date", "doc_values": True},
                            "last_seen": {"type": "date", "doc_values": True},
                            "match": {"type": "string", "index": "not_analyzed", "doc_values": True},
                            "md5": {"type": "string", "index": "not_analyzed", "doc_values": True},
                            "positives": {"type": "integer", "doc_values": True},
                            "ruleset_name": {"type": "string", "index": "not_analyzed", "doc_values": True},
                            "scans": {"type": "nested"},
                            "sha1": {"type": "string", "index": "not_analyzed", "doc_values": True},
                            "sha256": {"type": "string", "index": "not_analyzed", "doc_values": True},
                            "size": {"type": "integer", "doc_values": True},
                            "subject": {"type": "string", "index": "not_analyzed", "doc_values": True},
                            "total": {"type": "integer", "doc_values": True},
                            "type": {"type": "string", "index": "not_analyzed", "doc_values": True},
                        },
                        "dynamic_templates": [
                            {"notanalyzed": {
                                "match": "*",
                                "match_mapping_type": "string",
                                "mapping": {
                                    "type": "string",
                                    "index": "not_analyzed",
                                    "doc_values": True
                                }
                            }
                            }
                        ]
                    }
                }
            }
            try:
                self.es.indices.create(index=self.index_name, body=json.dumps(mapping))
            except Exception as e:
                print("Error creating the index in elasticsearch", e)

    def get_connection(self):
        if self.login is not None and self.password is not None:
            self.conn = Elasticsearch(
                [self.cfg["es_url"]],
                http_auth=(self.cfg["es_username"], self.cfg["es_password"]))
        else:
            self.conn = Elasticsearch([self.cfg["es_url"]])

    def bulk(self, bulk):
        helpers.bulk(self.conn, bulk)

