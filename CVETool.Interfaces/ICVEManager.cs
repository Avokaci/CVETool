using CVETool.Entities;
using System;
using System.Collections.Generic;

namespace CVETool.Interfaces
{
    public interface ICVEManager
    {
        public void AutoInit();
        public string[] LoadJson();
        public void CreateCVEs();
        public void SaveCVEsToDatabase();
        public List<CVE> GetAllCVEs();
        public CVE GetSingleCVE(string cveId);


    }
}
