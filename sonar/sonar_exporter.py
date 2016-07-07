#!/usr/bin/env python
import logging
import sys
import time

import configargparse
import requests
from prometheus_client import start_http_server
from prometheus_client.core import GaugeMetricFamily, REGISTRY
from requests.packages.urllib3.exceptions import InsecureRequestWarning


class SonarCollector(object):
    def __init__(self, sonar_url, sonar_user, sonar_password, metrics="ncloc,coverage"):
        self.web_url = sonar_url.rstrip('/')
        self.rest_url = self.web_url + '/api'
        self.sonar_user = sonar_user
        self.sonar_password = sonar_password
        self.metrics = metrics

    # main collector
    def collect(self):
        session = requests.Session()
        session.trust_env = False
        session.auth = (self.sonar_user, self.sonar_password)
        session.verify = False

        req_string = self.rest_url + '/resources?metrics=' + self.metrics
        res = session.get(req_string)
        # METRIC: detailed test results
        c = GaugeMetricFamily('sonar_metrics', 'SonarQube Metrics', labels=['name', 'key'])
        try:
            if res:
                results = res.json()
                for result in results:
                    for msr in result['msr']:
                        c.add_metric([result['name'], msr['key']], msr['val'])

                yield c
            else:
                logging.error("Error fetching from " + req_string)
                logging.error(res)
        except KeyError:
            logging.error("Could not retrieve metrics from: " + self.metrics)
            logging.error("Check argument sonar_metrics")


if __name__ == "__main__":
    parser = configargparse.ArgumentParser()
    parser.add_argument('--sonar_url', type=str, required=True, env_var='sonar_url')
    parser.add_argument('--sonar_metrics', type=str, env_var='sonar_metrics', default='ncloc,coverage')
    parser.add_argument('--sonar_user', type=str, required=True, env_var='sonar_user')
    parser.add_argument('--sonar_password', type=str, required=True, env_var='sonar_password')
    parser.add_argument('--run_once', action='store_true')
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(message)s')

    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    REGISTRY.register(SonarCollector(args.sonar_url, args.sonar_user, args.sonar_password, args.sonar_metrics))

    if args.run_once:
        for x in REGISTRY.collect():
            logging.info(x)
            for y in x.samples:
                logging.info(y)
        sys.exit("runonce")

    start_http_server(9118)
    while True:
        time.sleep(1)
