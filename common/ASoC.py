#
# Copyright 2026 HCL America, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import requests
import urllib3
import time
import subprocess
import datetime
import io
import sys
import platform
import os
import json
from constants import (
    CLIENT_TYPE_A360_FORMAT, CLIENT_TYPE_FORMAT, DATACENTER_EU, DATACENTER_NA, DATACENTER_URL_ASOC_EU, DATACENTER_URL_ASOC_US,
    API_LOGIN, API_LOGOUT, API_TENANT_INFO, API_FILE_UPLOAD,
    API_SAST_SCAN, API_SCA_SCAN, API_SCAN_EXECUTIONS, API_APPS,
    API_SAST_EXECUTION, API_SCA_EXECUTION,
    API_ISSUES,
    API_REPORT_SECURITY_SCAN, API_REPORTS_FILTER, API_REPORT_DOWNLOAD,
    CONTENT_TYPE_JSON, CONTENT_TYPE_OCTET_STREAM,
    SCAN_STATUS_READY, SCAN_STATUS_ABORT,
    REPORT_WAIT_INTERVAL_SECS, REPORT_WAIT_TIMEOUT_SECS,
    MSG_ERROR_SUBMITTING_SCAN, MSG_ASOC_REPORT_STATUS, MSG_ASOC_APP_SUMMARY_ERROR,
    TIMESTAMP_FORMAT, VERSION,
)

# Disable SSL warnings when bypassing certificate verification
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class ASoC:
    def __init__(self, apikey, logger, datacenter="NA", allow_untrusted=False):
        self.apikey = apikey
        self.token = ""
        self.allow_untrusted = allow_untrusted
        self.logger = logger
        if datacenter == DATACENTER_EU:
            self.base_url = DATACENTER_URL_ASOC_EU
        elif datacenter == DATACENTER_NA:
            self.base_url = DATACENTER_URL_ASOC_US
        else:
            self.base_url = datacenter
    
    def getDataCenterURL(self):
        return self.base_url
    
    def login(self):
        if self.allow_untrusted:
            resp = requests.post(f"{self.base_url}{API_LOGIN}", json=self.apikey, verify=False)
        else:
            resp = requests.post(f"{self.base_url}{API_LOGIN}", json=self.apikey)
        if(resp.status_code == 200):
            jsonObj = resp.json()
            self.token = jsonObj["Token"]
            return True
        else:
            return False
        
    def logout(self):
        headers = {
            "Accept": CONTENT_TYPE_JSON,
            "Authorization": "Bearer "+self.token
        }
        if self.allow_untrusted:
            resp = requests.get(f"{self.base_url}{API_LOGOUT}", headers=headers, verify=False)
        else:
            resp = requests.get(f"{self.base_url}{API_LOGOUT}", headers=headers)
        if(resp.status_code == 200):
            self.token = ""
            return True
        else:
            return False
        
    def checkAuth(self):
        headers = {
            "Accept": CONTENT_TYPE_JSON,
            "Authorization": "Bearer "+self.token
        }
        if self.allow_untrusted:
            resp = requests.get(f"{self.base_url}{API_TENANT_INFO}", headers=headers, verify=False)
        else:
            resp = requests.get(f"{self.base_url}{API_TENANT_INFO}", headers=headers)
        return resp.status_code == 200
    
    def generateIRX(self, scanName, scan_flag, appscanBin, stdoutFilePath = "", configFile=None, secret_scanning=None, printio=True, scan_speed=""):
        #Build scan arguments
        args = [appscanBin, "prepare", "-n", scanName]
        if configFile:
            args.extend(["-c", configFile])
        if secret_scanning is not None:
            if secret_scanning == False:
                args.append("--noSecrets")
            elif secret_scanning == True:
                args.append("--enableSecrets")
        if scan_flag is not None:
            args.append(scan_flag)
        if scan_speed != "":
            args.extend(["-s", scan_speed])
        
        # Sanitize scanName to prevent path traversal (strip directory separators and components)
        safe_scan_name = os.path.basename(scanName)
        stdoutFile = os.path.join(stdoutFilePath, safe_scan_name+'_stdout.txt')
        # Ensure the parent directory exists
        dir_path = os.path.dirname(stdoutFile)
        if dir_path and not os.path.exists(dir_path):
            os.makedirs(dir_path, exist_ok=True)
        
        with io.open(stdoutFile, 'wb') as writer:
            process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            for line in iter(process.stdout.readline, b''):
                writer.write(line)
                if printio:
                    sys.stdout.write(line.decode('utf-8', errors='replace'))
                    sys.stdout.flush()
            process.wait()
        if(printio):
            print()
        irxPath = scanName + ".irx"
        if(os.path.exists(irxPath)):
            return irxPath
        else:
            return None
            
    def uploadFile(self, filePath):
        #files = {'name': (<filename>, <file object>, <content type>, <per-part headers>)}
        fileName = os.path.basename(filePath)
        files = {
            "uploadedFile": (fileName, open(filePath, 'rb'), CONTENT_TYPE_OCTET_STREAM),
            "fileName": (None, fileName)
        }
        headers = {
            "Accept": CONTENT_TYPE_JSON,
            "Authorization": "Bearer "+self.token
        }
        if self.allow_untrusted:
            resp = requests.post(f"{self.base_url}{API_FILE_UPLOAD}", headers=headers, files=files, verify=False)
        else:
            resp = requests.post(f"{self.base_url}{API_FILE_UPLOAD}", headers=headers, files=files)
        if(resp.status_code == 200):
            fileId = resp.json()["FileId"]
            return fileId
        return None
    
    def createSastScan(self, scanName, appId, irxFileId, comment="", personal=False):
        data = {
            "ScanName": scanName,
            "AppId": appId,
            "Comment": comment,
            "ApplicationFileId": irxFileId,
            "Personal": personal,
            "ClientType": self.getClientType()
        }
        headers = {
            "Content-Type": CONTENT_TYPE_JSON,
            "Accept": CONTENT_TYPE_JSON,
            "Authorization": "Bearer "+self.token
        }
        if self.allow_untrusted:
            resp = requests.post(f"{self.base_url}{API_SAST_SCAN}", headers=headers, json=data, verify=False)
        else:
            resp = requests.post(f"{self.base_url}{API_SAST_SCAN}", headers=headers, json=data)
        if(resp.status_code == 201):
            scanId = resp.json()["Id"]
            return scanId
        else:
            self.logger.error(MSG_ERROR_SUBMITTING_SCAN)
            self.logger.error(resp.json())
            return None

    def createScaScan(self, scanName, appId, irxFileId, comment="", personal=False):
        data = {
            "ScanName": scanName,
            "AppId": appId,
            "Comment": comment,
            "ApplicationFileId": irxFileId,
            "Personal": personal,
            "ClientType": self.getClientType()
        }
        headers = {
            "Content-Type": CONTENT_TYPE_JSON,
            "Accept": CONTENT_TYPE_JSON,
            "Authorization": "Bearer "+self.token
        }
        if self.allow_untrusted:
            resp = requests.post(f"{self.base_url}{API_SCA_SCAN}", headers=headers, json=data, verify=False)
        else:
            resp = requests.post(f"{self.base_url}{API_SCA_SCAN}", headers=headers, json=data)
        if(resp.status_code == 201):
            scanId = resp.json()["Id"]
            return scanId
        else:
            self.logger.error(MSG_ERROR_SUBMITTING_SCAN)
            self.logger.error(resp.json())
            return None
    
    def getScanStatus(self, scanId):
        """Get scan execution status and details using the Executions endpoint.
        
        Returns the latest execution object which includes:
        - Status: The scan status (Running, Ready, Abort, etc.)
        - All summary data (NIssuesFound, NCriticalIssues, NHighIssues, etc.)
        
        Returns None on error.
        """
        headers = {
            "Accept": CONTENT_TYPE_JSON,
            "Authorization": "Bearer "+self.token
        }
        url = f"{self.base_url}{API_SCAN_EXECUTIONS.format(scan_id=scanId)}"
        if self.allow_untrusted:
            resp = requests.get(url, headers=headers, verify=False)
        else:
            resp = requests.get(url, headers=headers)
        if(resp.status_code == 200):
            executions = resp.json()
            if executions and len(executions) > 0:
                return executions[0]
            return None
        else:
            self.logger.error(MSG_ASOC_REPORT_STATUS)
            self.logger.error(resp)
            return None
            
    def getApplication(self, id):
        headers = {
            "Accept": CONTENT_TYPE_JSON,
            "Authorization": "Bearer "+self.token
        }
        if self.allow_untrusted:
            resp = requests.get(f"{self.base_url}{API_APPS}", headers=headers, verify=False)
        else:
            resp = requests.get(f"{self.base_url}{API_APPS}", headers=headers)
        if(resp.status_code == 200):
            app_info = self.checkAppExists(resp.json(), id)
            return app_info
        else:
            self.logger.error(MSG_ASOC_APP_SUMMARY_ERROR)
            return None

    def checkAppExists(self, response, id):
        for item in response['Items']:
            if item['Id'] == id:
                return item  
        return None  

    def SastScanSummary(self, id, is_execution=False):
        if(is_execution):
            asoc_url = f"{self.base_url}{API_SAST_EXECUTION}"
        else:
            asoc_url = f"{self.base_url}{API_SAST_SCAN}"
        
        headers = {
            "Accept": CONTENT_TYPE_JSON,
            "Authorization": "Bearer "+self.token
        }
        
        if self.allow_untrusted:
            resp = requests.get(asoc_url+id, headers=headers, verify=False)
        else:
            resp = requests.get(asoc_url+id, headers=headers)
        
        if(resp.status_code == 200):
            return resp.json()
        else:
            self.logger.error(resp.status_code)
            self.logger.error(resp.text)
            return None
        
    def ScaScanSummary(self, id, is_execution=False):
        if(is_execution):
            asoc_url = f"{self.base_url}{API_SCA_EXECUTION}"
        else:
            asoc_url = f"{self.base_url}{API_SCA_SCAN}"
        
        headers = {
            "Accept": CONTENT_TYPE_JSON,
            "Authorization": "Bearer "+self.token
        }
        
        if self.allow_untrusted:
            resp = requests.get(asoc_url+id, headers=headers, verify=False)
        else:
            resp = requests.get(asoc_url+id, headers=headers)
        
        if(resp.status_code == 200):
            return resp.json()
        else:
            self.logger.error(resp.status_code)
            self.logger.error(resp.text)
            return None
        
    def getNonCompliantIssues(self, scanId):
        """Fetch non-compliant issues for a scan, grouped by severity.

        Calls the Issues API with policy filtering to get counts of issues
        that are Open, InProgress, Reopened, or New, grouped by Severity.

        Args:
            scanId: The scan ID to fetch issues for.

        Returns:
            A dict mapping severity names to counts, e.g.
            {"Critical": 5, "High": 10, "Medium": 3, "Low": 1, "Informational": 0},
            or None on error.
        """
        # Query string (URL-encoded): ?applyPolicies=All&$top=100&$apply=filter(Status eq 'Open' or Status eq 'InProgress' or Status eq 'Reopened')/groupby((Severity),aggregate($count as Count))
        query_string = (
            "?applyPolicies=All"
            "&%24top=100"
            "&%24apply=filter%28"
            "Status%20eq%20%27Open%27%20or%20"
            "Status%20eq%20%27InProgress%27%20or%20"
            "Status%20eq%20%27Reopened%27%29%2F"
            "groupby%28%28Severity%29%2Caggregate%28%24count%20as%20Count%29%29"
        )
        url = f"{self.base_url}{API_ISSUES}{scanId}{query_string}"
        headers = {
            "Accept": CONTENT_TYPE_JSON,
            "Authorization": "Bearer " + self.token
        }
        try:
            if self.allow_untrusted:
                resp = requests.get(url, headers=headers, verify=False)
            else:
                resp = requests.get(url, headers=headers)
            if resp.status_code == 200:
                response_json = resp.json()
                items = response_json.get("Items", [])
                result = {}
                for item in items:
                    severity = item.get("Severity", "Unknown")
                    count = item.get("Count", 0)
                    result[severity] = count
                return result
            else:
                self.logger.error(f"Error fetching non-compliant issues: {resp.status_code} - {resp.text}")
                return None
        except Exception as e:
            self.logger.error(f"Exception fetching non-compliant issues: {e}")
            return None

    def startReport(self, id, reportConfig):
        url = f"{self.base_url}{API_REPORT_SECURITY_SCAN}"+id
        headers = {
            "Accept": CONTENT_TYPE_JSON,
            "Authorization": "Bearer "+self.token
        }
        if self.allow_untrusted:
            resp = requests.post(url, headers=headers, json=reportConfig, verify=False)
        else:
            resp = requests.post(url, headers=headers, json=reportConfig)
        if(resp.status_code == 200):
            return resp.json()["Id"]
        else:
            return None
        
    def reportStatus(self, reportId):
        headers = {
            "Accept": CONTENT_TYPE_JSON,
            "Authorization": "Bearer "+self.token
        }
        if self.allow_untrusted:
            resp = requests.get(f"{self.base_url}{API_REPORTS_FILTER}"+reportId, headers=headers, verify=False)
        else:
            resp = requests.get(f"{self.base_url}{API_REPORTS_FILTER}"+reportId, headers=headers)
        if(resp.status_code == 200):
            return resp.json()
        else:
            self.logger.error(f"Error fetching report status for reportId {reportId}: {resp.status_code} - {resp.text}")
            return {"Status": SCAN_STATUS_ABORT, "Progress": 0}
            
    def waitForReport(self, reportId, intervalSecs=REPORT_WAIT_INTERVAL_SECS, timeoutSecs=REPORT_WAIT_TIMEOUT_SECS):
        status = None
        elapsed = 0
        while status not in [SCAN_STATUS_ABORT, SCAN_STATUS_READY] or elapsed >= timeoutSecs:
            status = self.reportStatus(reportId)
            elapsed += intervalSecs
            time.sleep(intervalSecs)   
        return status == SCAN_STATUS_READY
        
    def downloadReport(self, reportId, fullPath):
        headers = {
            "Accept": CONTENT_TYPE_JSON,
            "Authorization": "Bearer "+self.token
        }
        if self.allow_untrusted:
            resp = requests.get(f"{self.base_url}{API_REPORT_DOWNLOAD.format(report_id=reportId)}", headers=headers, verify=False)
        else:
            resp = requests.get(f"{self.base_url}{API_REPORT_DOWNLOAD.format(report_id=reportId)}", headers=headers)
        if(resp.status_code==200):
            report_bytes = resp.content
            with open(fullPath, "wb") as f:
                f.write(report_bytes)
            return True
        else:
            return False
    
    #Get current system timestamp
    def getTimeStamp(self):
        ts = time.time()
        return datetime.datetime.fromtimestamp(ts).strftime(TIMESTAMP_FORMAT)

    def getClientType(self):
        if "local_" in self.apikey.get("KeyId", ""):
            client_type = CLIENT_TYPE_A360_FORMAT.replace("<plugin-version>", VERSION)
        else:
            os_name = platform.system().lower()
            client_type = CLIENT_TYPE_FORMAT.replace("<os>", os_name).replace("<plugin-version>", VERSION)
        
        self.logger.info(f"Client Type: {client_type}")
        return client_type
