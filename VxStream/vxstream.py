#!/usr/bin/env python3.5

from os import path
from time import sleep
from ipaddress import ip_address

from magic import Magic
from requests.auth import HTTPBasicAuth
import requests

from cortexutils.analyzer import Analyzer


class HTTP:
    OK = 200
    BadRequest = 400
    TooManyRequests = 429
    json = "application/json"
    octetstream = "application/octet-stream"


class Environment:
    apk = "ANDROID"
    nix = "LINUX"
    macos = "MACOS"
    win = "WINDOWS"


RESPONSE_OK = 0
RESPONSE_ERROR = -1


class VxStream(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)

        self.service = self.getParam(
            "config.service",
            None,
            "VxStream Sandbox service is missing"
        )
        self.url = self.getParam(
            "config.url",
            None,
            "VxStream Sandbox URL is missing"
        )
        self.api = self.getParam(
            "config.api",
            None,
            "VxStream Sandbox API URL is missing"
        )
        self.apikey = self.getParam(
            "config.key",
            None,
            "VxStream Sandbox API key is missing"
        )
        self.secret = self.getParam(
            "config.secret",
            None,
            "VxStream Sandbox API secret is missing"
        )

        self.environmentid = self.getParam(
            "config.environmentid",
            100,
            None
        )

        self.graceperiod = self.getParam(
            "config.graceperiod",
            60 * 5,
            None
        )
        self.interval = self.getParam(
            "config.interval",
            30,
            None
        )
        self.timeout = self.getParam(
            "config.timeout",
            60 * 10,
            None
        )

        self.hybridanalysis = self.getParam(
            "config.hybridanalysis",
            True,
            None
        )
        self.nosharevt = self.getParam(
            "config.nosharevt",
            False,
            None
        )
        self.torenabledanalysis = self.getParam(
            "config.torenabledanalysis",
            False,
            None
        )

        self.headers = {
            "User-agent": "Cortex (https://github.com/CERT-BDF/Cortex) "
                          "VxStream Sandbox Analyzer"
        }

    def run(self):
        # self.config()

        self.result = {}
        self.hash, self.ipaddr, self.dom = set(), set(), set()

        if self.data_type == "file" or self.data_type == "url":
            if self.service == "FileAnalysis":
                self.target = self.get_param(
                    "file",
                    None,
                    "File is missing"
                )
                # determine file MIME type
                self.mime_type()
            elif self.service == "URLAnalysis":
                self.env = Environment.win
                self.target = self.get_param(
                    "data",
                    None,
                    "URL is missing"
                )
            else:
                return self.error("Invalid service")

            # check available analysis environments
            self.environment()
            # submit the file or URL for analysis
            self.submit()
            # wait for the analysis to be over
            self.heartbeat()
            # retrieve the report and populate results
            self.scan()
            # retrieve additional data and populate results
            self.enrich()
        else:  # domain, fqdn, hash, ip, port
            if self.service == "Search":
                self.target = self.get_param(
                    "data",
                    None,
                    "Search term is missing"
                )
                self.search()
            else:
                return self.error("Invalid service")

        # return the report
        return self.report(self.result)

    def mime_type(self):
        self.mime = Magic(mime=True).from_file(self.target)

        if self.mime == "application/java-archive" and \
                        path.splitext(self.target)[1] == ".apk":
            self.env = Environment.apk
        elif self.mime == "application/x-executable":
            self.env = Environment.nix
        elif self.mime == "application/x-mach-binary":  # macos
            self.env = Environment.macos
        # elif self.mime in win:  # windows; application/x-dosexec
        else:
            self.env = Environment.win

    def environment(self):
        url = self.url + "system/state"
        param = {
            "params": {
                "apikey": self.apikey,
                "secret": self.secret
            }
        }
        msg = "unsuccessful system state query"

        data = self.query(url, param, msg, json=True)

        if data:
            try:
                data = data["backend"]["nodes"][0]["environment"]
            except (KeyError, IndexError):
                self.apifrmterr(url)
            msg = "invalid or unavailable analysis environment(s)"

            tmp = [i.get("ID") for i in data if
                   i.get("architecture") == self.env]
            if not self.environmentid in tmp or not tmp:
                self.error(msg)

    def submit(self):
        url = self.api + "submit"
        param = {
            "auth": HTTPBasicAuth(self.apikey, self.secret),
            "data": {
                "environmentId": self.environmentid,
                "hybridanalysis": ("false", "true")[self.hybridanalysis],
                "nosharevt": ("false", "true")[self.nosharevt],
                "torenabledanalysis": ("false", "true")[self.torenabledanalysis]
            },
            "verify": False
        }
        msg = "unsuccessful submission"

        if self.data_type == "url":
            url += "url"
            param["data"]["analyzeurl"] = self.target
        else:  # file  # apk, windows
            param["files"] = {"file": open(self.target, 'rb')}

        data = self.post(url, param, msg, json=True)

        if data:
            try:
                self.sha256 = data["sha256"]
            except KeyError:
                self.apifrmterr(url)
        else:
            self.error(msg + ", exiting")

    def heartbeat(self):
        url = self.api + "state/" + self.sha256
        param = {
            "params": {
                "apikey": self.apikey,
                "secret": self.secret,
                "environmentId": self.environmentid
            }
        }
        msg = "unsuccessful heartbeat check"

        try:
            self.graceperiod = int(self.graceperiod)
            if self.graceperiod < 0:
                raise ValueError
        except ValueError:
            self.error("invalid grace period (%s) value" % self.graceperiod)
        try:
            self.interval = int(self.interval)
            if self.interval < 0:
                raise ValueError
        except ValueError:
            self.error("invalid interval (%s) value" % self.interval)
        try:
            self.timeout = int(self.timeout)
            if self.timeout < 0:
                raise ValueError
        except ValueError:
            self.error("invalid timeout (%s) value" % self.timeout)

        sleep(self.graceperiod)

        stopwatch = 0
        while stopwatch < self.timeout:
            data = self.query(url, param, msg, json=True)

            try:
                if data and data["state"] == "SUCCESS":
                    break
            except KeyError:
                self.apifrmterr(url)

            if stopwatch + self.interval <= self.timeout:
                tmp = self.interval
            else:
                tmp = self.timeout - stopwatch

            sleep(tmp)
            stopwatch += tmp

        if stopwatch >= self.timeout:
            self.error("report retrieval timed out")

    def scan(self):
        url = self.api + "scan/" + self.sha256
        param = {
            "params": {
                "apikey": self.apikey,
                "secret": self.secret,
                "environmentId": self.environmentid,
                "type": "json"
            }
        }
        msg = "unsuccessful report retrieval"

        data = self.query(url, param, msg, json=True)

        if data:
            try:
                data = data[0]
            except IndexError:
                self.apifrmterr(url)

            # results
            self.result = data.copy()
            self.result["type"] = self.data_type
            self.result["avdetect"] = data["avdetect"]
            self.result["url"] = self.url + "sample/" + self.sha256 + \
                                 "?environmentId=" + str(self.environmentid)

            self.result["htmlreport"] = self.url + \
                                        "file/report/html/{0}/{1}".format(
                                            self.sha256, self.environmentid
                                        )
            self.result["pdfreport"] = self.url + \
                                       "file/report/pdf/{0}/{1}".format(
                                           self.sha256, self.environmentid
                                       )
            # verdict
            self.result["taxonomy"] = self.build_taxonomy(
                data.get("verdict"),
                "VxStream Sandbox",
                "Report",
                data.get("threatlevel")
            )
            # iocs
            if data.get("compromised_hosts"):
                self.ipaddr |= set(data.get("compromised_hosts"))
            if data.get("hosts"):
                self.ipaddr |= set(data.get("hosts"))
            if data.get("domains"):
                self.dom |= set(data.get("domains"))
            self.ipaddr = sorted([ip_address(i) for i in self.ipaddr])
            self.ipaddr = [i for i in map(str, self.ipaddr)]
            self.dom = sorted(list(self.dom))
        else:
            self.error("report response data invalid: " + str(data))

    def enrich(self):
        url = self.api + "result/" + self.sha256
        param = {
            "params": {
                "apikey": self.apikey,
                "secret": self.secret,
                "environmentId": self.environmentid,
                "type": "json"
            }
        }
        msg = "unsuccessful retrieval of enrichment data"

        data = self.query(url, param, msg, json=True, check=False)

        if data:
            try:
                # data = data[0]
                data = data.get("analysis")
            except IndexError:
                self.apifrmterr(url)

            # dropped files
            tmp = data.get("runtime").get("dropped")
            self.result["dropped_total"] = tmp.get("real_total")
            self.result["dropped"] = \
                [{"filename": i.get("filename"), "path": i.get("vmpath"),
                  "sha256": i.get("sha256")} for i in tmp.get("file")]

    def search(self):
        if self.data_type == "hash":
            srch = "similar-to"
        elif self.data_type == "ip":
            srch = "host"
        elif self.data_type == "port":
            srch = "port"
        else:  # elif self.data_type == "domain" or self.data_type == "fqdn":
            srch = "domain"
        srch += ":" + self.target

        url = self.api + "search"
        param = {
            "params": {
                "apikey": self.apikey,
                "secret": self.secret,
                "query": srch
            }
        }
        msg = "unsuccessful search"

        data = self.query(url, param, msg, json=True)

        if data:
            try:
                data = data["result"]
            except IndexError:
                self.apifrmterr(url)

            # results
            self.result = {"hits": data.copy()}
            # query
            self.result["url"] = url + "/?apikey=" + self.apikey + "&" + \
                                "secret=" + self.secret + "&" + \
                                "query=" + srch
            self.result["search"] = srch
            # iocs
            self.hash = list(set(i.get("sha256") for i in data if
                                 i.get("verdict") == "malicious"))
            self.ipaddr, self.dom = [], []
        else:
            self.error("report response data invalid: " + str(data))

    def summary(self, report):
        if self.data_type == "file" or self.data_type == "url":
            return {
                "avdetect": report.get("avdetect"),
                "signature": report.get("vxfamily"),
                "tags": report.get("classification_tags"),
                "taxonomy": report.get("taxonomy"),
                "type": report.get("type")
            }
        else:  # domain, fqdn, hash, ip, port
            return {
                "count": len(report.get("hits"))
            }

    def artifacts(self, report):
        return [{"type": "ip", "value": i} for i in self.ipaddr] + \
               [{"type": "domain", "value": i} for i in self.dom] + \
               [{"type": "hash", "value": i} for i in self.hash]

    def post(self, url, param, msg, json=False, bin=False):
        return self.query(url, param, msg, post=True, json=json, bin=bin)

    def query(self, url, param, msg,
              post=False, json=False, bin=False, check=True):
        param["headers"] = self.headers

        if not post:
            res = requests.get(url, **param)
        else:
            res = requests.post(url, **param)

        msg = msg + " - "

        if res.status_code == HTTP.OK:
            if res.headers["Content-Type"] == HTTP.json:
                null = None  # to account for potential JSON null values
                data = res.json()
                if check:
                    if data.get("response_code") == RESPONSE_ERROR:
                        self.error(msg + data.get("response").get("error"))
                    elif data.get("response_code") == RESPONSE_OK and json:
                        return data["response"]
                    else:
                        self.error(msg + "unexpected JSON response code " +
                                   data["response_code"])
                else:
                    return data
            elif res.headers["Content-Type"] == HTTP.octetstream and bin:
                return res.content
            else:
                self.error(msg + "unexpected response content type " +
                           res.headers["Content-Type"])
        else:
            msg += "%s (HTTP " + str(res.status_code) + " " + res.reason + ")"
            if res.status_code == HTTP.BadRequest:
                self.error(msg % "file submission error")
            elif res.status_code == HTTP.TooManyRequests:
                self.error(msg % "API key quota has been reached")
            else:
                self.error(msg % "unspecified error")
        return None

    def apifrmterr(self, url):
        err = "API response data format differs for "
        self.error(err + url)

if __name__ == "__main__":
    VxStream().run()
