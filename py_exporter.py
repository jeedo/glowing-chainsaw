#!/usr/bin/env python
import json
import pprint
import sys
import threading
import time

import configargparse
import re
import redis
import requests
from requests import ConnectionError
from prometheus_client import start_http_server
from prometheus_client.core import CounterMetricFamily, REGISTRY
from prometheus_client.core import GaugeMetricFamily
from sseclient import SSEClient
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class SonarCollector(object):
    def __init__(self, sonar_url, sonar_user, sonar_password, sonar_projects):
        self.web_url = sonar_url.rstrip('/')
        self.rest_url = self.web_url + '/api'
        self.sonar_user = sonar_user
        self.sonar_password = sonar_password
        self.sonar_projects = sonar_projects.split(',') if sonar_projects else []

    # main collector
    def collect(self):
        session = requests.Session()
        session.trust_env = False
        session.auth = (self.sonar_user, self.sonar_password)
        session.verify = False

        req_string = self.rest_url + '/resources?metrics=ncloc,coverage'
        res = session.get(req_string)
        # METRIC: detailed test results
        c = GaugeMetricFamily('sonar_metrics', 'SonarQube Metrics',
                              labels=['name', 'key'])
        if res:
            results = res.json()
            #pp = pprint.PrettyPrinter()
            for result in results:
                # pp.pprint(result)
                for msr in result['msr']:
                    c.add_metric([result['name'], msr['key']], msr['val'])

            yield c
        else:
            print "Error fetching from " + req_string
            print res


        #for proj in self.sonar_projects:
            #res = session.get(self.web_url + '?metrics=ncloc,coverage')

class BambooCollector(object):
    def __init__(self, bamboo_url, bamboo_user, bamboo_password, bamboo_test_jobs):
        self.web_url = bamboo_url.rstrip('/')
        self.rest_url = self.web_url + '/rest/api/latest'
        self.bamboo_user = bamboo_user
        self.bamboo_password = bamboo_password
        self.bamboo_test_jobs = bamboo_test_jobs.split(',') if bamboo_test_jobs else []

    # parse the HTML from viewAgents.action and create a tally of hosts/status
    @staticmethod
    def tally_agent_info(dashboard_summary):
        # tally the nodes by host+status
        tally = {}
        for build in dashboard_summary['builds']:
            status = build['status']
            if 'agent' in build:
                res = re.match(r'^(dcspa\d\dl|csp_deploy|dummy\d+)', build['agent']['name'])
                if res:
                    host = res.group(1)
                else:
                    continue  # skip unknown agents
            else:
                host = 'none'

            if host not in tally:
                tally[host] = {}
            if status in tally[host]:
                tally[host][status] += 1
            else:
                tally[host][status] = 1

        return tally

    def collect(self):
        session = requests.Session()
        session.trust_env = False
        session.auth = (self.bamboo_user, self.bamboo_password)
        session.verify = False

        # METRIC: detailed test results
        c = GaugeMetricFamily('bamboo_test_results', 'Bamboo Test Results', labels=['name', 'job', 'className', 'methodName'])
        for job in self.bamboo_test_jobs:
            res = session.get(self.web_url + '/rest/api/latest/result/' + job + '/latest.json?expand=testResults.allTests')
            if res:
                results = res.json()
                for testResult in res.json()['testResults']['allTests']['testResult']:
                    c.add_metric([results['plan']['name'], job, testResult['className'], testResult['methodName']], testResult['status'] == 'successful')
            else:
                print "error fetching test results"
                print res
        yield c

        # METRIC: bamboo agent state
        c = GaugeMetricFamily('bamboo_build_state', 'Bamboo Build Dashboard', labels=['state', 'host'])
        res = session.get(self.web_url + '/build/admin/ajax/getDashboardSummary.action')
        if res:
            dashboard_summary = res.json()
            for host, values in self.tally_agent_info(dashboard_summary).iteritems():
                for state, state_count in values.iteritems():
                    c.add_metric([state, host], state_count)
            yield c
        else:
            print res

        # Collect results tagged
        d = {}
        r = session.get(
            self.web_url + '/rest/api/latest/result.json?favourite&expand=results.result.buildDurationInSeconds')
        if r.ok:
            # NOTE: this may return multiple results for the same plan - need to use highest build number
            results = r.json()
            for result in results['results']['result']:
                key = result['plan']['key']
                if key in d and d[key]['number'] < result['number']:
                    continue  # don't overwrite with older build
                d[key] = result
        else:
            print r

        # METRIC: build status (favourites)
        METRICS = ['buildNumber', 'buildDurationInSeconds']
        TEST_METRICS = ['failedTestCount', 'skippedTestCount', 'quarantinedTestCount', 'successfulTestCount']

        statusMetric = GaugeMetricFamily('build_results', 'Status of flagged plans', labels=['name', 'state'])
        testMetric = GaugeMetricFamily('test_counts', 'Test result counts', labels=['shortName', 'countType'])
        metrics = {x: GaugeMetricFamily(x, x, labels=['shortName']) for x in METRICS}
        for key, result in d.iteritems():
            statusMetric.add_metric([result['plan']['shortName'], result['state']], result['successful'])
            for name in TEST_METRICS:
                testMetric.add_metric([result['plan']['shortName'], name], result[name])
            for name, metric in metrics.iteritems():
                metric.add_metric([result['plan']['shortName']], result[name])

        yield statusMetric
        yield testMetric
        for metric in metrics.itervalues():
            yield metric


# consume the event stream from Dashing and save it into a global key=value
# TODO: gauge vs counter?  last-update time?
class EventConsumerThread(threading.Thread):
    def consume_event(self, data):
        id = data['id']
        if 'value' in data:
            self.bucket[id] = data['value']
        elif 'current' in data:
            self.bucket[id] = data['current']
        elif 'serverStatus' in data:
            self.bucket[id] = 1 if data['serverStatus'] == 'UP' else 0  # could be 'UNSURE'
        elif 'points' in data:
            self.bucket  # ignore
        elif 'items' in data:
            for item in data['items']:
                label = id + '_' + self.label_regex.sub('', item['label'])
                self.bucket[label] = item['value']
        else:
            print "unknown data"
            print data

    def __init__(self, event_url):
        threading.Thread.__init__(self)
        self.label_regex = re.compile('[^\w\d]')
        self.event_url = event_url
        self.bucket = {}

    def run(self):
        while True:
            try:
                messages = SSEClient(self.event_url)
                for msg in messages:
                    data = json.loads(msg.data)
                    self.consume_event(data)
            except ConnectionError as e:
                print "Error in EventConsumerThread: " + e.message
                print e.message
                time.sleep(5)  # wait 5 seconds


class EventStreamCollector(object):
    def __init__(self, event_url):
        self.thread = EventConsumerThread(event_url)
        self.thread.start()

    def collect(self):
        c = CounterMetricFamily('env_dashboard', 'Help text', labels=['id'])
        for k, v in sorted(self.thread.bucket.iteritems()):
            c.add_metric([k], v)
        yield c


class RedisCollector(object):
    def __init__(self, redis_host, redis_port=6379):
        self.r = redis.StrictRedis(host=redis_host, port=6379, db=0)

    def collect(self):
        c = CounterMetricFamily('redis', 'Help text', labels=['id'])
        for key in self.r.keys('*'):
            try:
                c.add_metric([key], float(self.r.get(key)))
            except ValueError:
                None  # who cares
        yield c


if __name__ == "__main__":
    # ./py_exporter.py --bamboo_url https://dcbamboo.service.dev:8443 --bamboo_user suparsag --bamboo_password Admin12345 --bamboo_test_jobs COS-COS1-DTOL --run_once
    parser = configargparse.ArgumentParser()
    parser.add_argument('--bamboo_url', type=str, required=True, env_var='bamboo_url')
    parser.add_argument('--bamboo_user', type=str, required=True, env_var='bamboo_user')
    parser.add_argument('--bamboo_password', type=str, required=True, env_var='bamboo_password')
    parser.add_argument('--bamboo_test_jobs', type=str, env_var='bamboo_test_jobs') # CSV of PRJ-XX-JOB, eg COS-COS1-DTOL
#    parser.add_argument('--dashing_event_url', type=str, required=True, env_var='dashing_event_url')
#    parser.add_argument('--redis_host', type=str, required=True, env_var='redis_host')
#    parser.add_argument('--redis_port', type=int, env_var='redis_port', default=6379)
    parser.add_argument('--run_once', action='store_true')
    parser.add_argument('--sonar_url', type=str, required=True, env_var='sonar_url')
    parser.add_argument('--sonar_user', type=str, required=True, env_var='sonar_user')
    parser.add_argument('--sonar_password', type=str, required=True, env_var='sonar_password')


    args = parser.parse_args()

    REGISTRY.register(BambooCollector(args.bamboo_url, args.bamboo_user, args.bamboo_password, args.bamboo_test_jobs))
#    REGISTRY.register(EventStreamCollector(args.dashing_event_url))  # http://192.168.99.100:3030/events
#    REGISTRY.register(RedisCollector(args.redis_host, args.redis_port))
    REGISTRY.register(SonarCollector(args.sonar_url, args.sonar_user, args.sonar_password, []))

    if args.run_once:
        # time.sleep(5) # wait for async
        pp = pprint.PrettyPrinter(indent=4)
        for collector in REGISTRY._collectors:
            # collector = BambooCollector(args.bamboo_url, args.bamboo_user, args.bamboo_password)
            print collector
            for x in collector.collect():
                pp.pprint(x.samples)
        sys.exit("runonce")

    start_http_server(9118)
    while True:
        time.sleep(1)
