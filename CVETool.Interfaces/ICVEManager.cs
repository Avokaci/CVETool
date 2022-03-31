using CVETool.Entities;
using System;
using System.Collections.Generic;

namespace CVETool.Interfaces
{
    public interface ICVEManager
    {
        public void AutoInit();
        public void LoadJson();
        public void CreateCVEs();
        public void SaveCVEsToDatabase();
        public List<CVE> GetAllCVEs();
        public CVE GetSingleCVE(string cveId);
        public List<CVE> GetAllFilteredCVEs(string attribute, string value);
        public List<CVE> GetAllYearRangeFilteredCVEs(string startYear, string endYear);
        public List<CVE> GetAllScoreRangeFilteredCVEs(double startScore, double endScore);
      


    }
}
