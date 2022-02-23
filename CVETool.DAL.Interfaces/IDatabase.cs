using CVETool.Entities;
using System;
using System.Collections.Generic;

namespace CVETool.DAL.Interfaces
{
    public interface IDatabase
    {
        public void SaveCVEsToDatabase(List<CVE> cveList);
        public bool CheckRecordExists(string cVEID);
        public List<CVE> GetAllCVEsFromDB();
        public CVE GetSingleCVEFromDB(string cveId);
     
    }
}
