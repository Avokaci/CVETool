using CVETool.Entities;
using System;
using System.Collections.Generic;

namespace CVETool.Interfaces
{
    public interface ICVEManager
    {
        public void PullAllYearRecords();
        public void PullCurrentYearRecords();
        public void LoadJson();
        public void CVEInit(JSONImport import);

        public List<CVE> GetAllCVEs();
        public CVE GetSingleCVE(string cveId);


    }
}
