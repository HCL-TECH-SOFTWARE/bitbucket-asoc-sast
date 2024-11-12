from bitbucket_pipes_toolkit import Pipe, get_logger, CodeInsights
from ASoC import ASoC
import requests
import os
import json
import time
import zipfile
import re
import datetime
import shutil

VERSION = "1.1.1"
REVISION_DATE = "2023-10-11"

logger = get_logger()

schema = {
    'SCAN_NAME': {'type': 'string', 'required': False, 'default': "HCL_ASoC_SAST"},
    'DATACENTER': {'type': 'string', 'required': False, 'default': "NA"},
    'SECRET_SCANNING': {'type': 'boolean', 'required': False, 'default': False},
    'CONFIG_FILE_PATH': {'type': 'string', 'required': False, 'default': ""},
    'REPO': {'type': 'string', 'required': False, 'default': ""},
    'BUILD_NUM': {'type': 'number', 'required': False, 'default': 0},
    'API_KEY_ID': {'type': 'string', 'required': True},
    'API_KEY_SECRET': {'type': 'string', 'required': True},
    'APP_ID': {'type': 'string', 'required': True},
    'TARGET_DIR': {'type': 'string', 'required': True, 'default': False},
    'DEBUG': {'type': 'boolean', 'required': False, 'default': False},
    'STATIC_ANALYSIS_ONLY': {'type': 'boolean', 'required': False, 'default': False},
    'OPEN_SOURCE_ONLY': {'type': 'boolean', 'required': False, 'default': False}
}

class AppScanOnCloudSAST(Pipe):
    asoc = None
    
    #Run SAST Scan Process
    def run(self):
        super().run()
        
        # Read Environment Vars
        env = dict(os.environ)

        # Read Provided Variables from BitBucket Pipeline
        scanName = self.get_variable('SCAN_NAME')
        apikeyid = self.get_variable('API_KEY_ID')
        apikeysecret = self.get_variable('API_KEY_SECRET')
        self.appID = self.get_variable('APP_ID')
        self.datacenter = self.get_variable('DATACENTER')
        self.debug = self.get_variable('DEBUG')
        self.cloneDir = self.get_variable('TARGET_DIR')
        self.secret_scanning = self.get_variable('SECRET_SCANNING')
        buildNum = self.get_variable('BUILD_NUM')
        self.static_analysis_only = self.get_variable('STATIC_ANALYSIS_ONLY')
        self.open_source_only = self.get_variable('OPEN_SOURCE_ONLY')
        
        #Read Variables from the Environment
        self.repo = env.get('BITBUCKET_REPO_SLUG', "")
        self.repo_full_name = env.get('BITBUCKET_REPO_FULL_NAME', "")
        branch = env.get('BITBUCKET_BRANCH', "")
        self.commit = env.get('BITBUCKET_COMMIT', "")
        projectKey = env.get('BITBUCKET_PROJECT_KEY', "")
        self.repoOwner = env.get('BITBUCKET_REPO_OWNER', "")
        self.cwd = os.getcwd()

        #ensure both SAO and OSO are not both selected
        if(self.static_analysis_only and self.open_source_only):
            logger.error("Cannot run IRGen with both 'Open Source Only' and 'Static Analysis Only' options")
            self.fail(message="Both OSO and SAO selected")
            return False

        #set SAO or OSO scan flags
        scan_flag = None
        if(self.static_analysis_only):
            logger.info("Setting scan mode to SAO")
            scan_flag = '-sao'
        if(self.open_source_only):
            logger.info("Setting scan mode to OSO")
            scan_flag = '-oso'

        configFile = None
        # Convert relative path to full path
        if len(self.get_variable('CONFIG_FILE_PATH')) > 0:
            configFile = os.path.join(self.cwd, self.get_variable('CONFIG_FILE_PATH'))

        apikey = {
            "KeyId": apikeyid,
            "KeySecret": apikeysecret
        }

        #self.code_insights = CodeInsights(self.repo, self.repoOwner, auth_type="authless")
        self.asoc = ASoC(apikey, self.datacenter)
        logger.info("Executing Pipe: HCL AppScan on Cloud SAST")
        logger.info(f"\tVersion: {VERSION} rev {REVISION_DATE}")
        if(self.debug):
            logger.setLevel('DEBUG')
            logger.info("Debug logging enabled")
        
        #valid chars for a scan name: alphanumeric + [.-_ ]
        scanName = re.sub('[^a-zA-Z0-9\s_\-\.]', '_', scanName)+"_"+self.getTimeStamp()
        comment = "This scan was created via API testing BitBucket Pipes"
        
        logger.info("========== Step 0: Preparation ====================")
        #Copy contents of the clone dir to the target dir
        logger.info(f"SCAN_NAME: {scanName}")
        logger.info(f"APP_ID: {self.appID}")
        logger.info(f"BUILD_NUM: {buildNum}")
        logger.info(f"TARGET_DIR: {self.cloneDir}")
        if configFile is not None:
            logger.info(f"CONFIG_FILE_PATH: {configFile}")
        else:
            logger.info(f"CONFIG_FILE_PATH: Not Specified")
        logger.info(f"DATACENTER: {self.datacenter}")
        logger.info(f"SECRET_SCANNING: {self.secret_scanning}")
        logger.info(f"DEBUG: {self.debug}")
        logger.debug(f"REPO: {self.repo}")
        logger.debug(f"REPO_FULL: {self.repo_full_name}")
        logger.debug(f"BRANCH: {branch}")
        logger.debug(f"COMMIT: {self.commit}")
        logger.debug(f"PROJECT_KEY: {projectKey}")
        logger.debug(f"REPO_OWNER: {self.repoOwner}")
        logger.debug(f"Current Working Dir: {self.cwd}")
        targetDir = os.path.join(self.cwd, "target")
        logger.debug(f"SCAN TARGET: {targetDir}")

        cwd_dir_list = os.listdir(self.cwd)
        logger.debug(cwd_dir_list)
        clone_dir_list = os.listdir(self.cloneDir)
        logger.debug(clone_dir_list)

        # Check if config file actually exists
        if configFile is not None:
            if not os.path.exists(configFile):
                logger.error(f"Config Path Does Not Exist: {configFile}")
                logger.error(f"Using Defaults")
                configFile = None


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
        if configFile is None:
            logger.info("Config file not specified. Using defaults.")
            
        irxPath = self.genIrx(scanName, appscanPath, targetDir, reportsDir, scan_flag, configFile, self.secret_scanning)
        if(irxPath is None):
            logger.error("IRX File Not Generated.")
            self.fail(message="Error Running ASoC SAST Pipeline")
            return False
        logger.info("========== Step 2: Complete =======================\n") 
        
        #Step 3: Run the Scan
        logger.info("========== Step 3: Run the Scan on ASoC ===========")
        self.scanID = self.runScan(scanName, self.appID, irxPath, comment, True)
        if(self.scanID is None):
            logger.error("Error creating scan")
            self.fail(message="Error Running ASoC SAST Pipeline")
            return False
        logger.info("========== Step 3: Complete =======================\n")   
        
        #Step 4: Get the Scan Summary
        logger.info("========== Step 4: Fetch Scan Summary =============")      
        summaryFileName = scanName+".json"
        summaryPath = os.path.join(reportsDir, summaryFileName)
        logger.debug("Fetching Scan Summary")
        summary = self.getScanSummary(self.scanID, summaryPath)
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
            logger.info(f'\t\tCritical Issues: {summary["critical_issues"]}')
            logger.info(f'\t\tHigh Issues: {summary["high_issues"]}')
            logger.info(f'\t\tMed Issues: {summary["medium_issues"]}')
            logger.info(f'\t\tLow Issues: {summary["low_issues"]}')
            logger.info(f'\t\tInfo Issues: {summary["info_issues"]}')
            logger.debug("Scan Summary:\n"+json.dumps(summary, indent=2))
        logger.info("========== Step 4: Complete =======================\n")

        #Step 5: Download the Scan Report
        logger.info("========== Step 5: Download Scan Report ===========")
        notes = ""
        if(len(self.repo)>0):
            notes += f"Bitbucket Repo: {self.repo} "
        if(buildNum!=0):
            notes += f"Build: {buildNum}"
        reportFileName = scanName+".html"
        reportPath = os.path.join(reportsDir, reportFileName)
        report = self.getReport(self.scanID, reportPath, notes)
        if(report is None):
            logger.error("Error downloading report")
            self.fail(message="Error Running ASoC SAST Pipeline")
            return False
        logger.info(f"Report Downloaded [{reportPath}]")
        logger.info("========== Step 5: Complete =======================\n")
        
        self.success(message="ASoC SAST Pipeline Complete")

    def createSummaryReport(self, scanSummaryJson):
        """
        ToDo: Create CodeInsights Report
        """

    #download and unzip SAClientUtil to {cwd}/saclient
    def getSAClient(self, saclientPath="saclient"):
        #Downloading SAClientUtil
        url = "https://cloud.appscan.com/api/v4/Tools/SAClientUtil?os=linux"
        logger.info("Downloading SAClientUtil Zip")
        r = requests.get(url, stream=True)
        if(r.status_code != 200):
            logger.error("Invalid HTTP code downloading SAClient Util")
            return False
        chunk_size = 4096
        xfered = 0
        start = time.time()
        save_path = os.path.join(self.cwd, "saclient.zip")
        with open(save_path, 'wb') as fd:
            for chunk in r.iter_content(chunk_size=chunk_size):
                fd.write(chunk)
                xfered += len(chunk)
                mb = round(xfered/1048576, 2)
                if(time.time()-start > 3):
                    logger.info(f"SAClientUtil Downloading: {mb}MB...")
                    start = time.time()
        mb = round(xfered/1048576, 2)
        logger.info(f"SAClientUtil Downloaded: {mb}MB")
        
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
    def genIrx(self, scanName, appscanPath, targetPath, reportsDir, scan_flag, configFile=None, secret_scanning=False):
        #Change Working Dir to the target directory
        logger.debug(f"Changing dir to target: [{targetPath}]")
        os.chdir(targetPath)
        logger.info("IRX Gen stdout will be saved to [reports]")
        logger.info(f"Secret Scanning Enabled: [{secret_scanning}]")

        logger.info("Running AppScan Prepare")
        irxFile = self.asoc.generateIRX(scanName, scan_flag, appscanPath, reportsDir, configFile, secret_scanning, self.debug)
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
            logger.info(f"IRX Path [{irxPath}]")
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
        if self.open_source_only:
            scanId = self.asoc.createScaScan(scanName, appId, fileId, comment)
        else:
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
        while(statusMsg["Items"][0].get("Status") not in ["Ready", "Abort"]):
            time.sleep(5)
            statusMsg = self.asoc.reportStatus(reportId)
            percent = statusMsg["Items"][0].get("Progress")
            logger.info(f"Report Progress: {percent}%")
        
        if(statusMsg["Items"][0].get("Status") != "Ready"):
            logger.error("Problem generating report")
            return None
        logger.info("Report Complete, downloading report")
        
        result = self.asoc.downloadReport(reportId, reportPath)
        if(not result):
            logger.error(f"Error Downloading Report")
        return os.path.exists(reportPath)
    
    def getScanSummary(self, scanId, summaryPath):
        summary = self.asoc.SastScanSummary(scanId)
        if(summary is None):
            logger.error("HTTP Error Code when getting scan summary")
            return None
        summaryDict = {
            "scan_name": summary["Name"],
            "scan_id": summary["Id"],
            "createdAt": summary["LatestExecution"]["CreatedAt"],
            "duration_seconds": summary["LatestExecution"]["ExecutionDurationSec"],
            "critical_issues": summary["LatestExecution"]["NCriticalIssues"],
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
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    