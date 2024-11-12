import requests
import time
import subprocess
import datetime
import io
import sys
import os
import json

class ASoC:
    def __init__(self, apikey, datacenter="NA"):
        self.apikey = apikey
        self.token = ""
        if datacenter == "EU":
            self.base_url = "https://eu.cloud.appscan.com"
        else:
            self.base_url = "https://cloud.appscan.com"
    
    def login(self):
        resp = requests.post(f"{self.base_url}/api/v4/Account/ApiKeyLogin", json=self.apikey)
        if(resp.status_code == 200):
            jsonObj = resp.json()
            self.token = jsonObj["Token"]
            return True
        else:
            return False
        
    def logout(self):
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer "+self.token
        }
        resp = requests.get(f"{self.base_url}/api/v4/Account/Logout", headers=headers)
        if(resp.status_code == 200):
            self.token = ""
            return True
        else:
            return False
        
    def checkAuth(self):
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer "+self.token
        }
        resp = requests.get(f"{self.base_url}/api/v4/Account/TenantInfo", headers=headers)
        return resp.status_code == 200
    
    def generateIRX(self, scanName, scan_flag, appscanBin, stdoutFilePath = "", configFile=None, secret_scanning=False, printio=True):
        #Build scan arguments
        args = [appscanBin, "prepare", "-n", scanName]
        if configFile:
            args.extend(["-c", configFile])
        if secret_scanning:
            args.append("--enableSecrets")
        if scan_flag is not None:
            args.append(scan_flag)
        
        stdoutFile = os.path.join(stdoutFilePath, scanName+'_stdout.txt')
        
        with io.open(stdoutFile, 'wb') as writer, io.open(stdoutFile, 'rb') as reader:
            process = subprocess.Popen(args, stdout=writer)
            while process.poll() is None:
                if(printio):
                    sys.stdout.write(reader.read().decode('ascii'))
                time.sleep(0.5)
            if(printio):
                sys.stdout.write(str(reader.read().decode('ascii')))
        if(printio):
            sys.stdout.flush()
            print()
        irxPath = scanName + ".irx"
        if(os.path.exists(irxPath)):
            return irxPath
        else:
            return None
            
    def uploadFile(self, filePath):
        #files = {'name': (<filename>, <file object>, <content type>, <per-part headers>)}
        files = {
            "uploadedFile": ("test.irx", open(filePath, 'rb'), 'application/octet-stream'),
            "fileName": (None, "test.irx")
        }
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer "+self.token
        }
        resp = requests.post(f"{self.base_url}/api/v4/FileUpload", headers=headers, files=files)
        if(resp.status_code == 200):
            fileId = resp.json()["FileId"]
            return fileId
        return None
    
    def createSastScan(self, scanName, appId, irxFileId, comment=""):
        data = {
            "ScanName": scanName,
            "AppId": appId,
            "Comment": comment,
            "ApplicationFileId": irxFileId
        }
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": "Bearer "+self.token
        }
        resp = requests.post(f"{self.base_url}/api/v4/Scans/Sast/", headers=headers, json=data)
        if(resp.status_code != 201):
            print(f"Error submitting scan")
            print(resp.json())
        if(resp.status_code == 201):
            scanId = resp.json()["Id"]
            return scanId
            
        return None

    def createScaScan(self, scanName, appId, irxFileId, comment=""):
        data = {
            "ScanName": scanName,
            "AppId": appId,
            "Comment": comment,
            "ApplicationFileId": irxFileId
        }
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": "Bearer "+self.token
        }
        resp = requests.post(f"{self.base_url}/api/v4/Scans/Sca/", headers=headers, json=data)
        if(resp.status_code != 201):
            print(f"Error submitting scan")
            print(resp.json())
        if(resp.status_code == 201):
            scanId = resp.json()["Id"]
            return scanId
            
        return None
    
    def getScanStatus(self, scanId):
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer "+self.token
        }
        resp = requests.get(f"{self.base_url}/api/v4/Scans/"+scanId, headers=headers)
        if(resp.status_code == 200):
            return resp.json()["LatestExecution"]["Status"]
        else:
            print(f"ASoC Report Status")
            print(resp)
            return "Abort"
            
    def getApplication(self, id):
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer "+self.token
        }
        resp = requests.get(f"{self.base_url}/api/v4/Apps/", headers=headers)
        if(resp.status_code == 200):
            app_info = self.checkAppExists(resp.json(), id)
            return app_info
        else:
            print(f"ASoC App Summary Error Response")
            return None

    def checkAppExists(self, response, id):
        for item in response['Items']:
            if item['Id'] == id:
                return item  
        return None  

    def SastScanSummary(self, id, is_execution=False):
        if(is_execution):
            asoc_url = f"{self.base_url}/api/v4/Scans/SastExecution/"
        else:
            asoc_url = f"{self.base_url}/api/v4/Scans/Sast/"
        
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer "+self.token
        }
        
        resp = requests.get(asoc_url+id, headers=headers)
        
        if(resp.status_code == 200):
            return resp.json()
        else:
            print(resp.status_code)
            print(resp.text)
            return None
        
    def ScaScanSummary(self, id, is_execution=False):
        if(is_execution):
            asoc_url = f"{self.base_url}/api/v4/Scans/ScaExecution/"
        else:
            asoc_url = f"{self.base_url}/api/v4/Scans/Sca/"
        
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer "+self.token
        }
        
        resp = requests.get(asoc_url+id, headers=headers)
        
        if(resp.status_code == 200):
            return resp.json()
        else:
            print(resp.status_code)
            print(resp.text)
            return None
        
    def startReport(self, id, reportConfig):
        url = f"{self.base_url}/api/v4/Reports/Security/Scan/"+id
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer "+self.token
        }
        resp = requests.post(url, headers=headers, json=reportConfig)
        if(resp.status_code == 200):
            return resp.json()["Id"]
        else:
            return None
        
    def reportStatus(self, reportId):
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer "+self.token
        }
        resp = requests.get(f"{self.base_url}/api/v4/Reports?filter=Id%20eq%20"+reportId, headers=headers)
        if(resp.status_code == 200):
            return resp.json()
        else:
            return {"Status": "Abort", "Progress": 0}
            
    def waitForReport(self, reportId, intervalSecs=3, timeoutSecs=60):
        status = None
        elapsed = 0
        while status not in ["Abort","Ready"] or elapsed >= timeoutSecs:
            status = self.reportStatus(reportId)
            elapsed += intervalSecs
            time.sleep(intervalSecs)   
        return status == "Ready"
        
    def downloadReport(self, reportId, fullPath):
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer "+self.token
        }
        resp = requests.get(f"{self.base_url}/api/v4/Reports/"+reportId+"/Download", headers=headers)
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
        return datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d_%H-%M-%S')
    
        
    
    
        
        