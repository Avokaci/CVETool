using CVETool.DAL.Interfaces;
using CVETool.Entities;
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
        string _connectionString;
        SqlConnection con;
        SqlCommand cmd;

        public Database(List<CVE> cveList)
        {
            _connectionString = "Server=localhost\\SQLEXPRESS;Database=CVEDB;Trusted_Connection=True;";
            con = new SqlConnection(_connectionString);
            con.Open();
            string sql = "SELECT version()";
            cmd = new SqlCommand(sql, con);
            //Create tables
            cmd.CommandText = "DROP TABLE IF EXISTS CVE";
            cmd.ExecuteNonQuery();
            cmd.CommandText = @"CREATE TABLE CVE(Id INT IDENTITY(1, 1) PRIMARY KEY , 
                                CVEId VARCHAR(255),
                                CWEId VARCHAR(255), 
                                VulnerabilityType VARCHAR(255),
                                Description VARCHAR(max),
                                Publishdate VARCHAR(255),
                                ModificationDate VARCHAR(255),
                                Score float,
                                ExploitExists VARCHAR(255),
                                Access VARCHAR(255),
                                Complexity VARCHAR(255),
                                Authentication VARCHAR(255),
                                Confidentiality VARCHAR(255),
                                Integrity VARCHAR(255),
                                Avaialability VARCHAR(255)
                                )";
            cmd.ExecuteNonQuery();
           SaveCVEsToDatabase(cveList);
        }

        public void SaveCVEsToDatabase(List<CVE> cveList)
        {
            foreach (var item in cveList)
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
    }
}
