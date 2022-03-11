using CVETool.DAL.Interfaces;
using CVETool.Entities;
using CVETool.Utilities;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SqlClient;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CVETool.DAL
{
    public class Database : IDatabase
    {
        LogWriter logger = new LogWriter();
        string _connectionString;
        SqlConnection con;
        SqlCommand cmd;
        List<CVE> _cveList = new List<CVE>();

        //Constructor for empty DB to create from scratch loading all existing CVE records from all years
        public Database(List<CVE> cveList)
        {
            _connectionString = "Server=localhost\\SQLEXPRESS;Database=CVEDB;Trusted_Connection=True;";
            con = new SqlConnection(_connectionString);
            con.Open();
            string sql = "SELECT version()";
            cmd = new SqlCommand(sql, con);
            //Create tables
            //cmd.CommandText = "DROP TABLE IF EXISTS CVE";
            //cmd.ExecuteNonQuery();
            //cmd.CommandText = @"CREATE TABLE CVE(Id INT IDENTITY(1, 1) PRIMARY KEY , 
            //                    CVEId VARCHAR(255),
            //                    CWEId VARCHAR(255), 
            //                    VulnerabilityType VARCHAR(255),
            //                    Description VARCHAR(max),
            //                    Publishdate VARCHAR(255),
            //                    ModificationDate VARCHAR(255),
            //                    Score float,
            //                    ExploitExists VARCHAR(255),
            //                    Access VARCHAR(255),
            //                    Complexity VARCHAR(255),
            //                    Authentication VARCHAR(255),
            //                    Confidentiality VARCHAR(255),
            //                    Integrity VARCHAR(255),
            //                    Avaialability VARCHAR(255)
            //                    )";
            //cmd.ExecuteNonQuery();
            //SaveCVEsToDatabase(cveList);
            _cveList = cveList;
        }

        public void SaveCVEsToDatabase()
        {
            int progressCount = 0;

            logger.LogToConsoleProcessInfo("Started inserting all new CVE records into database");
            foreach (CVE item in _cveList)
            {
                if (!CheckRecordExists(item.CVEId))
                {
                    if (!CheckRecordModified(item.CVEId, item.UpdateDate))
                    {
                        InsertRecord(item);                   
                    }
                    else
                    {
                        ModifyRecord(item);
                    }
                }
                progressCount++;
                if (progressCount % 1000 == 0)
                {
                    int progressPercentage = (int)Math.Round((double)(progressCount * 100 / _cveList.Count));
                    logger.LogToConsoleObjectInfo("Creating database records for CVEs: " + progressPercentage + "%");
                }
            }
            logger.LogToConsoleProcessInfo("Finished inserting all new CVE records into database");

        }

        public bool CheckRecordExists(string cVEID)
        {
            cmd = new SqlCommand("select count(*) from dbo.CVE where CVEId='" + cVEID + "'", con);
            int counter = Convert.ToInt32(cmd.ExecuteScalar());
            if (counter > 0)
                return true;
            return false;
        }
        public bool CheckRecordModified(string cVEID, string itemModDateString)
        {         
            cmd = new SqlCommand("select ModificationDate from dbo.CVE where CVEId='" + cVEID + "'", con);
            DateTime dbModDate = Convert.ToDateTime(cmd.ExecuteScalar());
            DateTime itemModDate = Convert.ToDateTime(itemModDateString);
            string dbModDateString = dbModDate.ToString("s");
            if (itemModDate > dbModDate && dbModDateString != "0001-01-01T00:00:00") //"0001-01-01T00:00Z" is returned by db when column value couldn't be found -> in this case record does not exist yet
                return true;
            return false;
        }
        public void InsertRecord(CVE item)
        {
            cmd = new SqlCommand("insert into CVE(CVEId,CWEId,VulnerabilityType,Description," +
                "Publishdate,ModificationDate,Score,ExploitExists,Access," +
                "Complexity,Authentication,Confidentiality,Integrity,Avaialability) " +
                           "values(@CVEId,@CWEId,@VulnerabilityType,@Description," +
                "@Publishdate,@ModificationDate,@Score,@ExploitExists,@Access," +
                "@Complexity,@Authentication,@Confidentiality,@Integrity,@Avaialability)", con);
            cmd.Parameters.AddWithValue("CVEId", item.CVEId);
            cmd.Parameters.AddWithValue("CWEId", item.CWEId);
            cmd.Parameters.AddWithValue("VulnerabilityType", item.VulnerabilityType);
            cmd.Parameters.AddWithValue("Description", item.Description);
            cmd.Parameters.AddWithValue("Publishdate", item.PublishDate);
            cmd.Parameters.AddWithValue("ModificationDate", item.UpdateDate);
            cmd.Parameters.AddWithValue("Score", item.Score);
            cmd.Parameters.AddWithValue("ExploitExists", item.ExploitExists);
            cmd.Parameters.AddWithValue("Access", item.Access);
            cmd.Parameters.AddWithValue("Complexity", item.Complexity);
            cmd.Parameters.AddWithValue("Authentication", item.Authentication);
            cmd.Parameters.AddWithValue("Confidentiality", item.Confidentiality);
            cmd.Parameters.AddWithValue("Integrity", item.Integrity);
            cmd.Parameters.AddWithValue("Avaialability", item.Availability);
            cmd.ExecuteNonQuery();
        }
        public void ModifyRecord(CVE item)
        {
            cmd = new SqlCommand("update CVE set " +
                "CVEId = @CVEId, CWEId=@CWEId,VulnerabilityType=@VulnerabilityType,Description=@Description," +
                "Publishdate=@Publishdate,ModificationDate=@ModificationDate,Score=@Score,ExploitExists=@ExploitExists," +
                "Access=@Access,Complexity=@Complexity,Authentication=@Authentication," +
                "Confidentiality=@Confidentiality, Integrity=@Integrity,Avaialability= @Avaialability " +
                "where CVEId='" + item.CVEId + "'", con);
            cmd.Parameters.AddWithValue("CVEId", item.CVEId);
            cmd.Parameters.AddWithValue("CWEId", item.CWEId);
            cmd.Parameters.AddWithValue("VulnerabilityType", item.VulnerabilityType);
            cmd.Parameters.AddWithValue("Description", item.Description);
            cmd.Parameters.AddWithValue("Publishdate", item.PublishDate);
            cmd.Parameters.AddWithValue("ModificationDate", item.UpdateDate);
            cmd.Parameters.AddWithValue("Score", item.Score);
            cmd.Parameters.AddWithValue("ExploitExists", item.ExploitExists);
            cmd.Parameters.AddWithValue("Access", item.Access);
            cmd.Parameters.AddWithValue("Complexity", item.Complexity);
            cmd.Parameters.AddWithValue("Authentication", item.Authentication);
            cmd.Parameters.AddWithValue("Confidentiality", item.Confidentiality);
            cmd.Parameters.AddWithValue("Integrity", item.Integrity);
            cmd.Parameters.AddWithValue("Avaialability", item.Availability);
            cmd.ExecuteNonQuery();
        }

        public List<CVE> GetAllCVEsFromDB()
        {
            List<CVE> cveList = new List<CVE>();
            cmd.CommandText = "SELECT * FROM dbo.CVE";
            using (SqlDataReader reader = cmd.ExecuteReader())
            {
                while (reader.Read())
                {
                    CVE item = new CVE(
                        reader["CVEId"].ToString(),
                        reader["CWEId"].ToString(),
                        reader["VulnerabilityType"].ToString(),
                        reader["Description"].ToString(),
                        reader["Publishdate"].ToString(),
                        reader["ModificationDate"].ToString(),
                        Convert.ToDouble( reader["Score"]),
                        reader["ExploitExists"].ToString(),
                        reader["Access"].ToString(),
                        reader["Complexity"].ToString(),
                        reader["Authentication"].ToString(),
                        reader["Confidentiality"].ToString(),
                        reader["Integrity"].ToString(),
                        reader["Avaialability"].ToString()
                        );           
                    cveList.Add(item);
                }
                return cveList;
            }
        }

        //was intended for searching for single record, but not needed in Frontend as angular mat table already provides this feature
        public CVE GetSingleCVEFromDB(string cveId)
        {
            cmd.CommandText = "SELECT * FROM dbo.CVE where CVEId='" + cveId + "'";
            using (SqlDataReader reader = cmd.ExecuteReader())
            {
                CVE item = null;
                while (reader.Read())
                {
                     item = new CVE(
                       reader["CVEId"].ToString(),
                       reader["CWEId"].ToString(),
                       reader["VulnerabilityType"].ToString(),
                       reader["Description"].ToString(),
                       reader["Publishdate"].ToString(),
                       reader["ModificationDate"].ToString(),
                       Convert.ToDouble(reader["Score"]),
                       reader["ExploitExists"].ToString(),
                       reader["Access"].ToString(),
                       reader["Complexity"].ToString(),
                       reader["Authentication"].ToString(),
                       reader["Confidentiality"].ToString(),
                       reader["Integrity"].ToString(),
                       reader["Avaialability"].ToString()
                       );
                    return item;
                }
                return item;

            }
        }

        //for filtering vulns, specific year, exploitexists, access, complexity, authentication, confidentiality, integrity, availability
        public List<CVE> GetAllFilteredCVEsFromDB(string attribute, string value)
        {
            List<CVE> cveList = new List<CVE>();
            cmd.CommandText = "SELECT * FROM dbo.CVE where " + attribute + " like '%" + value + "%'";
            using (SqlDataReader reader = cmd.ExecuteReader())
            {
                while (reader.Read())
                {
                    CVE item = new CVE(
                        reader["CVEId"].ToString(),
                        reader["CWEId"].ToString(),
                        reader["VulnerabilityType"].ToString(),
                        reader["Description"].ToString(),
                        reader["Publishdate"].ToString(),
                        reader["ModificationDate"].ToString(),
                        Convert.ToDouble(reader["Score"]),
                        reader["ExploitExists"].ToString(),
                        reader["Access"].ToString(),
                        reader["Complexity"].ToString(),
                        reader["Authentication"].ToString(),
                        reader["Confidentiality"].ToString(),
                        reader["Integrity"].ToString(),
                        reader["Avaialability"].ToString()
                        );
                    cveList.Add(item);
                }
                return cveList;
            }
        }
       
        //for filtering CVEs between year range
        public List<CVE> GetAllYearRangeFilteredCVEsFromDB(string startYear, string endYear)
        {
            List<CVE> cveList = new List<CVE>();
            cmd.CommandText = "SELECT * FROM dbo.CVE where Publishdate between '" + startYear + "-00-00T00:00Z' and '" + endYear + "-00-00T00:00Z'";
            using (SqlDataReader reader = cmd.ExecuteReader())
            {
                while (reader.Read())
                {
                    CVE item = new CVE(
                    reader["CVEId"].ToString(),
                    reader["CWEId"].ToString(),
                    reader["VulnerabilityType"].ToString(),
                    reader["Description"].ToString(),
                    reader["Publishdate"].ToString(),
                    reader["ModificationDate"].ToString(),
                    Convert.ToDouble(reader["Score"]),
                    reader["ExploitExists"].ToString(),
                    reader["Access"].ToString(),
                    reader["Complexity"].ToString(),
                    reader["Authentication"].ToString(),
                    reader["Confidentiality"].ToString(),
                    reader["Integrity"].ToString(),
                    reader["Avaialability"].ToString()
                    );
                    cveList.Add(item);


                }
                return cveList;
            }
        }

        //for filtering CVEs score range
        public List<CVE> GetAllScoreRangeFilteredCVEsFromDB(double startScore, double endScore)
        {
            List<CVE> cveList = new List<CVE>();
            cmd.CommandText = "SELECT * FROM dbo.CVE where Score between " + Convert.ToDouble( startScore) + " and " + Convert.ToDouble(endScore);
            using (SqlDataReader reader = cmd.ExecuteReader())
            {
                while (reader.Read())
                {
                    CVE item = new CVE(
                    reader["CVEId"].ToString(),
                    reader["CWEId"].ToString(),
                    reader["VulnerabilityType"].ToString(),
                    reader["Description"].ToString(),
                    reader["Publishdate"].ToString(),
                    reader["ModificationDate"].ToString(),
                    Convert.ToDouble(reader["Score"]),
                    reader["ExploitExists"].ToString(),
                    reader["Access"].ToString(),
                    reader["Complexity"].ToString(),
                    reader["Authentication"].ToString(),
                    reader["Confidentiality"].ToString(),
                    reader["Integrity"].ToString(),
                    reader["Avaialability"].ToString()
                    );
                    cveList.Add(item);


                }
                return cveList;
            }
        }


    }
}
