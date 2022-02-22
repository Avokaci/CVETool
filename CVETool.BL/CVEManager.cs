using CVETool.DAL;
using CVETool.Entities;
using CVETool.Interfaces;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;

namespace CVETool.BL
{
    //stats: 
    //2002: 6769
    //2003: 1550
    //2004: 2707
    //2005: 4764
    //2006: 7140
    //2007: 6577
    //2008: 7170
    //2009: 5023
    //2010: 5190
    //2011: 4827
    //2012: 5835
    //2013: 6644
    //2014: 8847
    //2015: 8561
    //2016: 10474
    //2017: 16529
    //2018: 16716
    //2019: 16517
    //2020: 19162
    //2021: 18415
    //2022: 1538

    //Total: 180955 CVEs
    //Program: 115887 CVEs
    public class CVEManager: ICVEManager
    {
        public List<CVE> CVEs = new List<CVE>();
        Database db;

        //duration no file checking, no vulntype extraction, no db -->  loading files and creating objects --> 2min
        //duration no vulntype extraction, no db -->  file checking, loading files and creating objects --> 2min 5s
        //duration no db -->  file checking, loading files and creating objects, vulntype extraction, --> 10min 5s


        public void LoadJson()
        {
            string filepath = @"C:\Users\burak_y46me01\OneDrive\Desktop\CVETool\importFiles\";
            string[] files = Directory.GetFiles(filepath, "*.json", SearchOption.AllDirectories);

            if (files.Length == 0)
            {
                PullAllYearRecords();
            }
            else
            {
                PullCurrentYearRecords();
            }

            foreach (var file in files)
            {
                using (StreamReader r = new StreamReader(file))
                {
                    string json = r.ReadToEnd();
                    JSONImport import = JsonConvert.DeserializeObject<JSONImport>(json);
                    CVEInit(import);
                }
            }

        }
        public void CVEInit(JSONImport param)
        {
            
            for (int i = 0; i < param.CVE_Items.Count; i++)
            {
                string CVEId = "N/A";
                string CWEId = "N/A";
                string description = "N/A";
                string vulnType = "N/A";
                string publishDate = "N/A";
                string updateDate = "N/A";
                double score = 0;
                string exploit = "N/A";
                string access = "N/A";
                string complexity = "N/A";
                string auth = "N/A";
                string conf = "N/A";
                string integ = "N/A";
                string avail = "N/A";
                try
                {
                   CVEId = param.CVE_Items[i].cve.CVE_data_meta.ID;
                   CWEId = param.CVE_Items[i].cve.problemtype.problemtype_data[0].description[0].value;
                   description = param.CVE_Items[i].cve.description.description_data[0].value;
                   vulnType = getVulnType(description);
                   publishDate = param.CVE_Items[i].publishedDate;
                   updateDate = param.CVE_Items[i].lastModifiedDate;
                   score = Convert.ToDouble(param.CVE_Items[i].impact.baseMetricV2.cvssV2.baseScore);
                   exploit = getExploit(CVEId);
                   access = param.CVE_Items[i].impact.baseMetricV2.cvssV2.accessVector;
                   complexity = param.CVE_Items[i].impact.baseMetricV2.cvssV2.accessComplexity;
                   auth = param.CVE_Items[i].impact.baseMetricV2.cvssV2.authentication;
                   conf = param.CVE_Items[i].impact.baseMetricV2.cvssV2.confidentialityImpact;
                   integ = param.CVE_Items[i].impact.baseMetricV2.cvssV2.integrityImpact;
                   avail = param.CVE_Items[i].impact.baseMetricV2.cvssV2.availabilityImpact;
                }
                catch (Exception)  //for faulty records
                {

                    continue;
                }
              
                CVE vuln = new CVE(
                    CVEId,
                    CWEId, 
                    vulnType, 
                    description, 
                    publishDate,
                    updateDate, 
                    score, 
                    exploit, 
                    access, 
                    complexity, 
                    auth, 
                    conf, 
                    integ, 
                    avail               
                    );
                CVEs.Add(vuln);
            }
            db = new Database(CVEs);
            
        }
  

        private string getVulnType(string param)
        {
            //https://www.cvedetails.com/vulnerabilities-by-types.php
            //anfangs eine Liste genommen aber wegen der erhöhten dauer auf string zurückgegriffen --> o notation

            string vulnType = "";

            //DoS
            if (param.Contains("denial of service", StringComparison.CurrentCultureIgnoreCase))
            {
                vulnType += "DoS + ";
            }
            //Code Execution
            if (param.Contains("execute", StringComparison.CurrentCultureIgnoreCase))
            {
                vulnType += "Code Execution + ";
            }
            //Overflow
            if (param.Contains("buffer overflow", StringComparison.CurrentCultureIgnoreCase))
            {
                vulnType += "Overflow + ";
            }
            //Memory Corruption
            if (param.Contains("memory corruption", StringComparison.CurrentCultureIgnoreCase))
            {
                vulnType += "Memory Corruption + ";
            }
            //SQL injection
            if (param.Contains("sql injection",StringComparison.CurrentCultureIgnoreCase))
            {
                vulnType += "SQL injection + ";
            }
            //XSS
            if (param.Contains("Cross-site scripting (XSS)", StringComparison.CurrentCultureIgnoreCase))
            {
                vulnType += "XSS + ";
            }
            //Directory Traversal
            if (param.Contains("directory traversal", StringComparison.CurrentCultureIgnoreCase))
            {
                vulnType += "Directory Traversal + ";
            }
            //HTTP Response Splitting
            if (param.Contains("HTTP response splitting", StringComparison.CurrentCultureIgnoreCase))
            {
                vulnType += "HTTP Response Splitting + ";
            }
            //Bypas something
            if (param.Contains("bypass", StringComparison.CurrentCultureIgnoreCase))
            {
                vulnType += "Bypas something + ";
            }
            //Gain Information   word information doesnt match every record
            if (param.Contains("information", StringComparison.CurrentCultureIgnoreCase))
            {
                vulnType += "Gain Information + ";
            }
            //Gain Privileges
            if (param.Contains("privilege", StringComparison.CurrentCultureIgnoreCase))
            {
                vulnType += "Gain Privileges + ";
            }
            //CSRF
            if (param.Contains("CSRF", StringComparison.CurrentCultureIgnoreCase))
            {
                vulnType += "CSRF + ";
            }
            //File Inclusion
            if (param.Contains("file inclusion", StringComparison.CurrentCultureIgnoreCase))
            {
                vulnType += "File Inclusion + ";
            }
            
     
            return vulnType.Substring(0,vulnType.Length-3);
        }
        //TODO
        private string getExploit(string param)
        {          
            return "N/A";
        }

        public void PullCurrentYearRecords()
        {
            string currentYear = DateTime.Now.Year.ToString();
            string downloadPath = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-" + currentYear + ".json.zip";
            string zipPath = @"C:\Users\burak_y46me01\Downloads\nvdcve-1.1-" + currentYear + ".json.zip";
            string filePath = @"C:\Users\burak_y46me01\OneDrive\Desktop\CVETool\importFiles\nvdcve-1.1-" + currentYear + ".json";

            WebClient webClient = new WebClient();
            if (File.Exists(zipPath) || File.Exists(filePath))
            {
                File.Delete(zipPath);
                File.Delete(filePath);
            }
            webClient.DownloadFile(downloadPath, zipPath);
            System.IO.Compression.ZipFile.ExtractToDirectory(zipPath, @"C:\Users\burak_y46me01\OneDrive\Desktop\CVETool\importFiles");

        }

        public void PullAllYearRecords()
        {
             int currentYear = DateTime.Now.Year;

            for (int year = 2002; year < currentYear+1; year++)
            {
                string downloadPath = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-" + year + ".json.zip";
                string zipPath = @"C:\Users\burak_y46me01\Downloads\nvdcve-1.1-" + year + ".json.zip";
                string filePath = @"C:\Users\burak_y46me01\OneDrive\Desktop\CVETool\importFiles\nvdcve-1.1-" + year + ".json";

                WebClient webClient = new WebClient();
                if (File.Exists(zipPath) || File.Exists(filePath))
                {
                    File.Delete(zipPath);
                    File.Delete(filePath);
                }
                webClient.DownloadFile(downloadPath, zipPath);
                System.IO.Compression.ZipFile.ExtractToDirectory(zipPath, @"C:\Users\burak_y46me01\OneDrive\Desktop\CVETool\importFiles");
            }
        }
    }
}
