using CVETool.Entities;
using System;
using System.Collections.Generic;

namespace CVETool.Interfaces
{
    public interface ICVEManager
    {
        public void LoadJson();
        public void CreateCVEs();
        public void SaveCVEsToDatabase();
        public void AutoInit();
        public List<CVE> GetAllCVEs();
        public List<CVE> GetAllFilteredCVEs(string attribute, string value);
        public List<CVE> GetAllYearRangeFilteredCVEs(string startYear, string endYear);
        public List<CVE> GetAllScoreRangeFilteredCVEs(double startScore, double endScore);

        //GetSingleCVE not used
        public CVE GetSingleCVE(string cveId);

    }
}
