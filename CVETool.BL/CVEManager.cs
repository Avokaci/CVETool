using CVETool.DAL;
using CVETool.Entities;
using CVETool.Interfaces;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;

namespace CVETool.BL
{
    public class CVEManager: ICVEManager
    {
        public List<CVE> CVEs = new List<CVE>();
        Database db;

        public void LoadJson()
        {
            string filepath = @"C:\Users\burak_y46me01\OneDrive\Desktop\CVETool\importFiles\";
            string[] files = Directory.GetFiles(filepath, "*.json", SearchOption.AllDirectories);

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
            //Duration without extracting VulnType: 1:30 min
            //Duration with extracting VulnType: 8:30 min (string operations & ifs)
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
            //db = new Database(CVEs);
            
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

    }
}
