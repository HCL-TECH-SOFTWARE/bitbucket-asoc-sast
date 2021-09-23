from bitbucket_pipes_toolkit import Pipe, get_logger
from ASoC import ASoC
import requests
import os
import json
import time
import zipfile
import re
import datetime
import shutil

logger = get_logger()

schema = {
    'SCAN_NAME': {'type': 'string', 'required': False, 'default': "HCL_ASoC_SAST"},
    'REPO': {'type': 'string', 'required': False, 'default': ""},
    'BUILD_NUM': {'type': 'number', 'required': False, 'default': 0},
    'API_KEY_ID': {'type': 'string', 'required': True},
    'API_KEY_SECRET': {'type': 'string', 'required': True},
    'APP_ID': {'type': 'string', 'required': True},
    'TARGET_DIR': {'type': 'string', 'required': True, 'default': False},
    'DEBUG': {'type': 'boolean', 'required': False, 'default': False}
}

class AppScanOnCloudSAST(Pipe):
    asoc = None
    
    #Run SAST Scan Process
    def run(self):
        super().run()
        
        #Read Provided Variables from BitBucket
        scanName = self.get_variable('SCAN_NAME')
        apikeyid = self.get_variable('API_KEY_ID')
        apikeysecret = self.get_variable('API_KEY_SECRET')
        appId = self.get_variable('APP_ID')
        self.debug = self.get_variable('DEBUG')
        self.cloneDir = self.get_variable('TARGET_DIR')
        repo = self.get_variable('REPO')
        buildNum = self.get_variable('BUILD_NUM')
        
        self.cwd = os.getcwd()
        apikey = {
          "KeyId": apikeyid,
          "KeySecret": apikeysecret
        }
        
        self.asoc = ASoC(apikey)
        logger.info("Executing Pipe: HCL AppScan on Cloud SAST")
        logger.info("\trev 2021-08-24")
        if(self.debug):
            logger.setLevel('DEBUG')
            logger.info("Debug logging enabled")
        
        
        #valid chars for a scan name: alphanumeric + [.-_ ]
        scanName = re.sub('[^a-zA-Z0-9\s_\-\.]', '_', scanName)+"_"+self.getTimeStamp()
        configFile = None
        comment = "This scan was created via API testing BitBucket Pipes"
        
        logger.info("========== Step 0: Preparation ====================")
        #Copy contents of the clone dir to the target dir
        targetDir = os.path.join(self.cwd, "target")
        logger.info(f"Copying [{self.cwd}] to [{targetDir}]")
        if(shutil.copytree(self.cloneDir, targetDir) is None):
            logger.error("Cannot copy build clone dir into target dir")
            self.fail(message="Error Running ASoC SAST Pipeline")
            return False
            
        #Create the saclient dir if it doesn not exist
        saclientPath = os.path.join(self.cwd, "saclient")
        if(not os.path.isdir(saclientPath)):
            logger.debug(f"SAClient Path [{saclientPath}] does not exist")
            try:
                os.mkdir(saclientPath)
                logger.info(f"Created dir [{saclientPath}]")
            except:
                logger.error(f"Error creating saclient path [{saclientPath}]")
                self.fail(message="Error Running ASoC SAST Pipeline")
                return False
            if(not os.path.isdir(saclientPath)):
                logger.error(f"Error creating saclient path [{saclientPath}]")
                self.fail(message="Error Running ASoC SAST Pipeline")
                return False
                
        #Create Reports Dir if it does not exist 
        reportsDir = os.path.join(self.cwd, "reports")
        if(not os.path.isdir(reportsDir)):
            logger.debug(f"Reports dir doesn't exists [{reportsDir}]")
            os.mkdir(reportsDir)
            if(not os.path.isdir(reportsDir)):
                logger.error(f"Cannot create reports dir! [{reportsDir}]")
                self.fail(message="Error Running ASoC SAST Pipeline")
                return False
            else:
                logger.info(f"Created dir [{reportsDir}]")
        #Make sure we have write permission on the reports dir
        logger.info("Setting permissions on reports dir")
        os.chmod(reportsDir, 755)
        logger.info("========== Step 0: Complete =======================\n")
        
        #Step 1: Download the SACLientUtil
        logger.info("========== Step 1: Download SAClientUtil ==========")
        appscanPath = self.getSAClient(saclientPath)
        if(appscanPath is None):
            logger.error("AppScan Path not found, something went wrong with SACLientUtil Download?")
            self.fail(message="Error Running ASoC SAST Pipeline")
            return False
        logger.info("========== Step 1: Complete =======================\n")
        
        
        #Step 2: Generate the IRX
        logger.info("========== Step 2: Generate IRX File ==============")
        
        irxPath = self.genIrx(scanName, appscanPath, targetDir, reportsDir, configFile)
        if(irxPath is None):
            logger.error("IRX File Not Generated.")
            self.fail(message="Error Running ASoC SAST Pipeline")
            return False
        logger.info("========== Step 2: Complete =======================\n")
        
        
        #Step 3: Run the Scan
        logger.info("========== Step 3: Run the Scan on ASoC ===========")
        scanId = self.runScan(scanName, appId, irxPath, comment, True)
        if(scanId is None):
            logger.error("Error creating scan")
            self.fail(message="Error Running ASoC SAST Pipeline")
            return False
        logger.info("========== Step 3: Complete =======================\n")
        
        
        #Step 4: Get the Scan Summary
        logger.info("========== Step 4: Fetch Scan Summary =============")      
        summaryFileName = scanName+".json"
        summaryPath = os.path.join(reportsDir, summaryFileName)
        logger.debug("Fetching Scan Summary")
        summary = self.getScanSummary(scanId, summaryPath)
        if(summary is None):
            logger.error("Error getting scan summary")
        else:
            seconds = summary["duration_seconds"] % (24 * 3600)
            hour = seconds // 3600
            seconds %= 3600
            minutes = seconds // 60
            seconds %= 60
            durationStr = "%d:%02d:%02d" % (hour, minutes, seconds)
            logger.info("Scan Summary:")
            logger.info(f"\tDuration: {durationStr}")
            logger.info(f'\tTotal Issues: {summary["total_issues"]}')
            logger.info(f'\t\tHigh Issues: {summary["high_issues"]}')
            logger.info(f'\t\tMed Issues: {summary["medium_issues"]}')
            logger.info(f'\t\tLow Issues: {summary["low_issues"]}')
            logger.debug("Scan Summary:\n"+json.dumps(summary, indent=2))
        logger.info("========== Step 4: Complete =======================\n")
        

        #Step 5: Download the Scan Report
        logger.info("========== Step 5: Download Scan Report ===========")
        notes = ""
        if(len(repo)>0):
            notes += f"Bitbucket Repo: {repo} "
        if(buildNum!=0):
            notes += f"Build: {buildNum}"
        reportFileName = scanName+".html"
        reportPath = os.path.join(reportsDir, reportFileName)
        report = self.getReport(scanId, reportPath, notes)
        if(report is None):
            logger.error("Error downloading report")
            self.fail(message="Error Running ASoC SAST Pipeline")
            return False
        logger.info(f"Report Downloaded [{reportPath}]")
        logger.info("========== Step 5: Complete =======================\n")
        
        self.success(message="ASoC SAST Pipeline Complete")
        
    #download and unzip SAClientUtil to {cwd}/saclient
    def getSAClient(self, saclientPath="saclient"):
        #Downloading SAClientUtil
        url = "https://cloud.appscan.com/api/SCX/StaticAnalyzer/SAClientUtil?os=linux"
        logger.info("Downloading SAClientUtil Zip")
        r = requests.get(url, stream=True)
        if(r.status_code != 200):
            logger.error("Invalid HTTP code downloading SAClient Util")
            return False
        file_size = int(r.headers["content-length"])
        disposition = r.headers["content-disposition"]
        chunk_size = 4096
        xfered = 0
        percent = 0
        start = time.time()
        save_path = os.path.join(self.cwd, "saclient.zip")
        with open(save_path, 'wb') as fd:
            for chunk in r.iter_content(chunk_size=chunk_size):
                fd.write(chunk)
                xfered += len(chunk)
                percent = round((xfered/file_size)*100)
                if(time.time()-start > 3):
                    logger.info(f"SAClientUtil Download: {percent}%")
                    start = time.time()
        logger.info(f"SAClientUtil Download: {percent}%")
        
        #Extract the downloaded file
        logger.info("Extracting SAClientUtil Zip")
        with zipfile.ZipFile(save_path, 'r') as zip_ref:
            zip_ref.extractall(saclientPath)

        #Make sure all the SAClientUtil Files can be read and executed
        logger.info("Setting permissions on SACLientUtil Files")
        for root, dirs, files in os.walk(saclientPath):
            for d in dirs:
                os.chmod(os.path.join(root, d), 755)
            for f in files:
                os.chmod(os.path.join(root, f), 755)
        
        #Find the appscan executable
        logger.debug("Finding appscan bin path")
        appscanPath = None
        dirs = os.listdir(saclientPath)
        for file in dirs:
            appscanPath = os.path.join(self.cwd, saclientPath, file, "bin", "appscan.sh")
            
        if(os.path.exists(appscanPath)):
            logger.debug(f"AppScan Bin Path [{appscanPath}]")
        else:
            logger.error("Something went wrong setting up the SAClientUtil")
            logger.error(f"AppScan Bin [{appscanPath}] not found!")
            return None
        
        #Return the appscan executable path
        return appscanPath
        
    #generate IRX file for target directory
    def genIrx(self, scanName, appscanPath, targetPath, reportsDir, configFile=None):
        #Change Working Dir to the target directory
        logger.debug(f"Changing dir to target: [{targetPath}]")
        os.chdir(targetPath)
        logger.info("IRX Gen stdout will be saved to [reports]")
        logger.info("Running AppScan Prepare")
        irxFile = self.asoc.generateIRX(scanName, appscanPath, reportsDir, configFile, self.debug)
        if(irxFile is None):
            logger.error("IRX Not Generated")
            return None
            
        irxPath = os.path.join(targetPath, irxFile)
        logPath = os.path.join(targetPath, scanName+"_logs.zip")
        
        #Change working dir back to the previous current working dir
        logger.debug(f"Changing dir to previous working dir: [{self.cwd}]")
        os.chdir(self.cwd)
        
        #Check if logs dir exists, if it does copy to the reports dir to be saved
        if(os.path.exists(logPath)):
            logger.debug(f"Logs Found [{logPath}]")
            logger.debug("Copying logs to reports dir")
            newLogPath = os.path.join(reportsDir, scanName+"_logs.zip")
            res = shutil.copyfile(logPath, newLogPath)
            if(res):
                logger.info(f"Logs Saved: [{res}]")
                
        #Verify the IRX File Exists
        if(os.path.exists(irxPath)):
            logger.debug(f"IRX Path [{irxPath}]")
            return irxPath
        
        logger.error(f"IRX File does not exist [{irxPath}]")
        return None
    
    #Create the SAST scan based on an IRX File
    #If Wait=True the function will sleep until the scan is complete
    def runScan(self, scanName, appId, irxPath, comment="", wait=True):
        #Verify that ASoC is logged in, if not then login
        logger.debug("Login to ASoC")
        if(not self.asoc.checkAuth()):
            if(self.asoc.login()):
                logger.info("Successfully logged into ASoC API")
            else:
                logger.error("Error logging into ASoC!")
                return None
               
        #Verify that appId exists
        logger.debug(f"Checking AppId [{appId}]")
        app = self.asoc.getApplication(appId)
        if(app):
            appName = app["Name"]
            logger.info("App Found:")
            logger.info(f"\t[{appName}] - [{appId}]")
        else:
            logger.error("Invalid AppId: App Not Found!")
            return None
        
        scanName = appName+"_"+scanName
        #Upload the IRX File and get a FileId
        logger.debug("Uploading IRX File")
        fileId = self.asoc.uploadFile(irxPath)
        if(fileId is None):
            logger.error("Error uploading IRX File")
        logger.debug(f"IRX FileId: [{fileId}]")
        
        #Run the Scan
        logger.debug("Running Scan")
        scanId = self.asoc.createSastScan(scanName, appId, fileId, comment)
        
        if(scanId):
            logger.info("Scan Created")
            logger.info(f"ScanId: [{scanId}]")
        else:
            logger.error("Scan not created!")
            return None
            
        #If Wait=False, return now with scanId
        if(wait == False):
            logger.info("Do not wait for scan to complete, return immediatly")
            return scanId
        
        logger.info("Waiting for scan to complete (status=Ready)")
        status = self.asoc.getScanStatus(scanId)
        c = 0
        start = time.time()
        while(status not in ["Ready", "Abort"]):
            if(time.time()-start >= 120):
                logger.info(f"\tScan still running...(status={status})")
                start = time.time()
            time.sleep(15)
            status = self.asoc.getScanStatus(scanId)
        
        if(status == "Ready"):
            logger.info(f"Scan [{scanId}] Complete")
        else:
            logger.error("ASoC returned an invalid status... check login?")
            logger.error("If script continues, the scan might not be complete")
        return scanId
    
    #Download a report based on a scan
    def getReport(self, scanId, reportPath, note=""):
        reportConfig = {
            "Configuration": {
					"Summary": True,
					"Overview": True,
					"TableOfContent": True,
					"Advisories": True,
					"FixRecommendation": True,
					"MinimizeDetails": True,
					"ReportFileType": "Html",
					"Title": "HCL ASoC SAST Security Report",
                    "Notes": note
				}
        }
        reportId = self.asoc.startReport(scanId, reportConfig)
        if(reportId is None):
            logger.error("Error starting report")
            return None
        
        statusMsg = self.asoc.reportStatus(reportId)
        while(statusMsg["Status"] not in ["Ready", "Abort"]):
            time.sleep(5)
            statusMsg = self.asoc.reportStatus(reportId)
            percent = statusMsg["Progress"]
            logger.info(f"Report Progress: {percent}%")
        
        if(statusMsg["Status"] != "Ready"):
            logger.error("Problem generating report")
            return None
        logger.info("Report Complete, downloading report")
        
        result = self.asoc.downloadReport(reportId, reportPath)
        if(not result):
            logger.error(f"Error Downloading Report")
        return os.path.exists(reportPath)
    
    def getScanSummary(self, scanId, summaryPath):
        summary = self.asoc.scanSummary(scanId)
        if(summary is None):
            logger.error("HTTP Error Code when getting scan summary")
            return None
        summaryDict = {
            "scan_name": summary["Name"],
            "scan_id": summary["Id"],
            "createdAt": summary["LatestExecution"]["ExecutionDurationSec"],
            "duration_seconds": summary["LatestExecution"]["ExecutionDurationSec"],
            "high_issues": summary["LatestExecution"]["NHighIssues"],
            "medium_issues": summary["LatestExecution"]["NMediumIssues"],
            "low_issues": summary["LatestExecution"]["NLowIssues"],
            "info_issues": summary["LatestExecution"]["NInfoIssues"],
            "total_issues": summary["LatestExecution"]["NIssuesFound"],
            "opensource_licenses": summary["LatestExecution"]["NOpenSourceLicenses"],
            "opensource_packages": summary["LatestExecution"]["NOpenSourcePackages"]
        }
        logger.info(f"Scan summary saved [{summaryPath}]")
        with open(summaryPath, "w") as summaryFile:
            json.dump(summary, summaryFile, indent=4)
        return summaryDict
    
    #Get current system timestamp
    def getTimeStamp(self):
        ts = time.time()
        return datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d_%H-%M-%S')
    
        
if __name__ == '__main__':
    pipe = AppScanOnCloudSAST(pipe_metadata='/pipe.yml', schema=schema)
    pipe.run()
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    