using CVETool.DAL;
using CVETool.Entities;
using CVETool.Interfaces;
using CVETool.Utilities;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace CVETool.BL
{
    public class CVEManagerImpl:ICVEManager
    {
        public List<CVE> CVEs = new List<CVE>();
        LogWriter logger = new LogWriter();
        Database db;
        JSONImport import;
        string[] filesNew = null;

        //from scratch
        //duration pulling and loading json files: 0:0:14
        //duration for creating CVE objects: 0:14:7
        //duration for creating database records of cve objects: 2:45:33

  


        public void AutoInit()
        {
            //pulling and loading json files
            var watch = System.Diagnostics.Stopwatch.StartNew();         
            filesNew = LoadJson();
            watch.Stop();
            TimeSpan timeSpan = watch.Elapsed;
            logger.LogToConsoleProcessInfo("Elapsed time for pulling and loading JSON files: " + timeSpan.Hours + ":" + timeSpan.Minutes + ":" + timeSpan.Seconds);
           
            //creating CVE objects from json files
            watch = System.Diagnostics.Stopwatch.StartNew();
            CreateCVEs();
            watch.Stop();
            timeSpan = watch.Elapsed;
            logger.LogToConsoleProcessInfo("Elapsed time for creating CVE objects: " + timeSpan.Hours + ":" + timeSpan.Minutes + ":" + timeSpan.Seconds);

            //creating database records from cve objects
            watch = System.Diagnostics.Stopwatch.StartNew();
            db = new Database(CVEs);
            SaveCVEsToDatabase();
            watch.Stop();
            timeSpan = watch.Elapsed;
            logger.LogToConsoleProcessInfo("Elapsed time for creating database records of CVE objects: " + timeSpan.Hours + ":" + timeSpan.Minutes + ":" + timeSpan.Seconds);


        }
        public string[] LoadJson()
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
            filesNew = Directory.GetFiles(filepath, "*.json", SearchOption.AllDirectories);
            return filesNew;
        }
        public void CreateCVEs()
        {
            foreach (var file in filesNew)
            {
                using (StreamReader r = new StreamReader(file))
                {
                    string json = r.ReadToEnd();
                    import = JsonConvert.DeserializeObject<JSONImport>(json);


                    var year = import.CVE_Items[0].cve.CVE_data_meta.ID.Substring(4, 4);
                    logger.LogToConsoleProcessInfo("Started creating CVE objects for year " + year);
                    for (int i = 0; i < import.CVE_Items.Count; i++)
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
                        //Cveid
                        try
                        {
                            CVEId = import.CVE_Items[i].cve.CVE_data_meta.ID;                                                
                        }
                        catch (Exception ex)  
                        {
                            CVEId = "N/A";                       
                        }
                        try
                        {
                            CWEId = import.CVE_Items[i].cve.problemtype.problemtype_data[0].description[0].value;
                           
                        }
                        catch (Exception)
                        {
                            CWEId = "N/A";
                            using (StreamWriter writer = File.AppendText(@"D:\errorLogs\creationError.txt"))
                            {
                                writer.WriteLine("Error while trying to create CVE with ID: " +CVEId + " Failed initializing cweid");
                            }
                        }
                        try
                        {
                            description = import.CVE_Items[i].cve.description.description_data[0].value;
                          
                        }
                        catch (Exception)
                        {
                            description = "N/A";
                            using (StreamWriter writer = File.AppendText(@"D:\errorLogs\creationError.txt"))
                            {
                                writer.WriteLine("Error while trying to create CVE with ID: " + CVEId + " Failed initializing description");
                            }
                        }
                        try
                        {
                            vulnType = GetVulnType(description);
                          
                        }
                        catch (Exception)
                        {
                            vulnType = "N/A";
                            using (StreamWriter writer = File.AppendText(@"D:\errorLogs\creationError.txt"))
                            {
                                writer.WriteLine("Error while trying to create CVE with ID: " + CVEId + " Failed initializing vulnType");
                            }
                        }
                        try
                        {
                            publishDate = import.CVE_Items[i].publishedDate;
                         
                        }
                        catch (Exception)
                        {
                            publishDate = "N/A";
                            using (StreamWriter writer = File.AppendText(@"D:\errorLogs\creationError.txt"))
                            {
                                writer.WriteLine("Error while trying to create CVE with ID: " + CVEId + " Failed initializing publishDate");
                            }
                        }
                        try
                        {
                            updateDate = import.CVE_Items[i].lastModifiedDate;
                            
                        }
                        catch (Exception)
                        {
                            updateDate = "N/A";
                            using (StreamWriter writer = File.AppendText(@"D:\errorLogs\creationError.txt"))
                            {
                                writer.WriteLine("Error while trying to create CVE with ID: " + CVEId + " Failed initializing updateDate");
                            }
                        }
                        try
                        {
                            score = Convert.ToDouble(import.CVE_Items[i].impact.baseMetricV2.cvssV2.baseScore);
                          
                        }
                        catch (Exception)
                        {
                            score = 0;
                            using (StreamWriter writer = File.AppendText(@"D:\errorLogs\creationError.txt"))
                            {
                                writer.WriteLine("Error while trying to create CVE with ID: " + CVEId + " Failed initializing score");
                            }
                        }
                        try
                        {
                            exploit = "https://www.google.at/search?q="+CVEId+"+exploit";
                         
                        }
                        catch (Exception)
                        {
                            exploit = "N/A";
                            using (StreamWriter writer = File.AppendText(@"D:\errorLogs\creationError.txt"))
                            {
                                writer.WriteLine("Error while trying to create CVE with ID: " + CVEId + " Failed initializing exploit");
                            }
                        }
                        try
                        {
                            access = import.CVE_Items[i].impact.baseMetricV2.cvssV2.accessVector;
                          
                        }
                        catch (Exception)
                        {
                            access = "N/A";
                            using (StreamWriter writer = File.AppendText(@"D:\errorLogs\creationError.txt"))
                            {
                                writer.WriteLine("Error while trying to create CVE with ID: " + CVEId + " Failed initializing access");
                            }
                        }
                        try
                        {
                            complexity = import.CVE_Items[i].impact.baseMetricV2.cvssV2.accessComplexity;
                           
                        }
                        catch (Exception)
                        {
                            complexity = "N/A";
                            using (StreamWriter writer = File.AppendText(@"D:\errorLogs\creationError.txt"))
                            {
                                writer.WriteLine("Error while trying to create CVE with ID: " + CVEId + " Failed initializing complexity");
                            }
                        }
                        try
                        {
                            auth = import.CVE_Items[i].impact.baseMetricV2.cvssV2.authentication;
                           
                        }
                        catch (Exception)
                        {
                            auth = "N/A";
                            using (StreamWriter writer = File.AppendText(@"D:\errorLogs\creationError.txt"))
                            {
                                writer.WriteLine("Error while trying to create CVE with ID: " + CVEId + " Failed initializing auth");
                            }
                        }
                        try
                        {
                            conf = import.CVE_Items[i].impact.baseMetricV2.cvssV2.confidentialityImpact;
                           
                        }
                        catch (Exception)
                        {
                            conf = "N/A";
                            using (StreamWriter writer = File.AppendText(@"D:\errorLogs\creationError.txt"))
                            {
                                writer.WriteLine("Error while trying to create CVE with ID: " + CVEId + " Failed initializing conf");
                            }
                        }
                        try
                        {
                            integ = import.CVE_Items[i].impact.baseMetricV2.cvssV2.integrityImpact;
                        }
                        catch (Exception)
                        {
                            integ = "N/A";
                            using (StreamWriter writer = File.AppendText(@"D:\errorLogs\creationError.txt"))
                            {
                                writer.WriteLine("Error while trying to create CVE with ID: " + CVEId + " Failed initializing integ");
                            }
                        }
                        try
                        {
                            avail = import.CVE_Items[i].impact.baseMetricV2.cvssV2.availabilityImpact;

                        }
                        catch (Exception)
                        {
                            avail = "N/A";
                            using (StreamWriter writer = File.AppendText(@"D:\errorLogs\creationError.txt"))
                            {
                                writer.WriteLine("Error while trying to create CVE with ID: " + CVEId + " Failed initializing avail");
                            }
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
                        if (i % 1000 == 0)
                        {
                            int progressPercentage = (int)Math.Round((double)(i * 100 / import.CVE_Items.Count));
                            logger.LogToConsoleObjectInfo("Creating CVEs progress: " + progressPercentage +"%");
                        }
                    }
                    logger.LogToConsoleProcessInfo("Finished creating CVE objects for year " + year);

                }
            }
            logger.LogToConsoleProcessInfo("Finished creating all CVE objects");

        }

        private string GetVulnType(string param)
        {
            //https://www.cvedetails.com/vulnerabilities-by-types.php
            //anfangs eine Liste genommen aber wegen der erhöhten dauer auf string zurückgegriffen --> o notation
            //https://dotnetcoretutorials.com/2020/02/06/performance-of-string-concatenation-in-c/

            //string vulnType = "";
            StringBuilder builder = new StringBuilder();

            //DoS
            if (param.Contains("denial of service", StringComparison.CurrentCultureIgnoreCase))
            {
                //vulnType += "DoS + ";
                builder.Append("DoS + ");
            }
            //Code Execution
            if (param.Contains("execute", StringComparison.CurrentCultureIgnoreCase)|| param.Contains("execution", StringComparison.CurrentCultureIgnoreCase))
            {
                //vulnType += "Code Execution + ";
                builder.Append("Code Execution + ");
            }
            //Overflow
            if (param.Contains("buffer overflow", StringComparison.CurrentCultureIgnoreCase))
            {
                //vulnType += "Overflow + ";
                builder.Append("Overflow + ");
            }
            //Memory Corruption
            if (param.Contains("memory corruption", StringComparison.CurrentCultureIgnoreCase))
            {
                //vulnType += "Memory Corruption + ";
                builder.Append("Memory Corruption + ");
            }
            //SQL injection
            if (param.Contains("sql injection", StringComparison.CurrentCultureIgnoreCase))
            {
                //vulnType += "SQL injection + ";
                builder.Append("SQL injection + ");
            }
            //XSS
            if (param.Contains("Cross-site scripting (XSS)", StringComparison.CurrentCultureIgnoreCase) || param.Contains("xss", StringComparison.CurrentCultureIgnoreCase) || param.Contains("Cross site", StringComparison.CurrentCultureIgnoreCase))
            {
                //vulnType += "XSS + ";
                builder.Append("XSS + ");
            }
            //Directory Traversal
            if (param.Contains("directory traversal", StringComparison.CurrentCultureIgnoreCase))
            {
                //vulnType += "Directory Traversal + ";
                builder.Append("Directory Traversal + ");
            }
            //HTTP Response Splitting
            if (param.Contains("HTTP response splitting", StringComparison.CurrentCultureIgnoreCase))
            {
                //vulnType += "HTTP Response Splitting + ";
                builder.Append("HTTP Response Splitting + ");
            }
            //Bypas something
            if (param.Contains("bypass", StringComparison.CurrentCultureIgnoreCase))
            {
                //vulnType += "Bypas something + ";
                builder.Append("Bypass something + ");
            }
            //Gain Information   word information doesnt match every record
            if (param.Contains("information", StringComparison.CurrentCultureIgnoreCase))
            {
                //vulnType += "Gain Information + ";
                builder.Append("Gain Information + ");
            }
            //Gain Privileges
            if (param.Contains("privilege", StringComparison.CurrentCultureIgnoreCase)|| param.Contains("elevate", StringComparison.CurrentCultureIgnoreCase))
            {
                //vulnType += "Gain Privileges + ";
                builder.Append("Gain Privileges + ");
            }
            //CSRF
            if (param.Contains("CSRF", StringComparison.CurrentCultureIgnoreCase))
            {
                //vulnType += "CSRF + ";
                builder.Append("CSRF + ");
            }
            //File Inclusion
            if (param.Contains("file inclusion", StringComparison.CurrentCultureIgnoreCase))
            {
                //vulnType += "File Inclusion + ";
                builder.Append("File Inclusion + ");
            }


            if (builder.Length > 3)
            {
                return builder.ToString().Substring(0, builder.ToString().Length - 3);
            }
            return "N/A";
        }
      

        private void PullCurrentYearRecords()
        {
            logger.LogToConsoleProcessInfo("Started pulling current CVE records");
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
            logger.LogToConsoleProcessInfo("Finished pulling current CVE records (" + currentYear + ")");


        }

        private void PullAllYearRecords()
        {
            int currentYear = DateTime.Now.Year;
            logger.LogToConsoleProcessInfo("Started pulling all CVE records");

            for (int year = 2002; year < currentYear + 1; year++)
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
                logger.LogToConsoleObjectInfo("Pulled CVE records from year " + year);
            }
            logger.LogToConsoleProcessInfo("Finished pulling all CVE records");

        }

        public void SaveCVEsToDatabase()
        {
            db = new Database(CVEs);
            db.SaveCVEsToDatabase();
        }
        public List<CVE> GetAllCVEs()
        {
            db = new Database(CVEs);
            return CVEs = db.GetAllCVEsFromDB();
        }

        public CVE GetSingleCVE(string cveId)
        {
            db = new Database(CVEs);
            CVE cve = db.GetSingleCVEFromDB(cveId);
            return cve;
        }

        public List<CVE> GetAllFilteredCVEs(string attribute, string value)
        {
            db = new Database(CVEs);
            List<CVE> cveList = db.GetAllFilteredCVEsFromDB(attribute,value);
            return cveList;
        }

        public List<CVE> GetAllYearRangeFilteredCVEs(string startYear, string endYear)
        {
            db = new Database(CVEs);
            List<CVE> cveList = db.GetAllYearRangeFilteredCVEsFromDB(startYear, endYear);
            return cveList;
        }

        public List<CVE> GetAllScoreRangeFilteredCVEs(double startScore, double endScore)
        {
            db = new Database(CVEs);
            List<CVE> cveList = db.GetAllScoreRangeFilteredCVEsFromDB(startScore, endScore);
            return cveList;
        }
    }
}

