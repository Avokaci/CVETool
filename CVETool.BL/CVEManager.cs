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

        public void LoadJson()
        {
            using (StreamReader r = new StreamReader(@"C:\Users\burak_y46me01\OneDrive\Desktop\CVETool\importFiles\nvdcve-1.1-2022.json"))
            {
                string json = r.ReadToEnd();
                JSONImport import = JsonConvert.DeserializeObject<JSONImport>(json);
                CVEInit(import);
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
                catch (Exception)
                {

                    continue;
                }
              

                string vulnTypee = getVulnType(param.CVE_Items[i].cve.description.description_data[0].value);
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
      
        }
        //TODO
        private string getVulnType(string param)
        {
            return "N/A";
        }
        //TODO
        private string getExploit(string param)
        {
            return "N/A";
        }

    }
}
