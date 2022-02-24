using CVETool.Entities;
using System;
using System.Collections.Generic;

namespace CVETool.DAL.Interfaces
{
    public interface IDatabase
    {
        public void SaveCVEsToDatabase();
        public bool CheckRecordExists(string cveId);
        public List<CVE> GetAllCVEsFromDB();
        public CVE GetSingleCVEFromDB(string cveId);
     
    }
}
