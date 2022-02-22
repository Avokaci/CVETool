using CVETool.DAL.Interfaces;
using CVETool.Entities;
using CVETool.Utilities;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CVETool.DAL
{
    public class Database:IDatabase
    {
        LogWriter logger = new LogWriter();
        string _connectionString;
        SqlConnection con;
        SqlCommand cmd;

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
            SaveCVEsToDatabase(cveList);
        }
        
        public void SaveCVEsToDatabase(List<CVE> cveList)
        {
            logger.LogToConsoleProcessInfo("Started inserting all new CVE records into database");
            foreach (var item in cveList)
            {
                if (!CheckRecordExists(item.CVEId))
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
               
            }
            logger.LogToConsoleProcessInfo("Finished inserting all new CVE records into database");

        }

        public bool CheckRecordExists(string cVEID)
        {
            cmd = new SqlCommand("select count(*) from dbo.CVE where CVEId='"+cVEID+"'", con);
            int counter = Convert.ToInt32(cmd.ExecuteScalar());
            if (counter > 0)
                return true;
            return false;
        }

         
    }
}
