using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CVETool.Entities
{
    public class CVE
    {
        private string _CVEId;
        private string _CWEId;
        private string _VulnerabilityType;
        private string _Description;
        private string _PublishDate;
        private string _UpdateDate;
        private double _Score;
        private string _ExploitExists;
        private string _Access;
        private string _Complexity;
        private string _Authentication;
        private string _Confidentiality;
        private string _Integrity;
        private string _Availability;

        public CVE(string cVEId, string cWEId, string vulnerabilityType, 
            string description, string publishDate, string updateDate, double score, 
            string exploitExists, string access, string complexity, 
            string authentication, string confidentiality, 
            string integrity, string availability)
        {
            _CVEId = cVEId;
            _CWEId = cWEId;
            _VulnerabilityType = vulnerabilityType;
            _Description = description;
            _PublishDate = publishDate;
            _UpdateDate = updateDate;
            _Score = score;
            _ExploitExists = exploitExists;
            _Access = access;
            _Complexity = complexity;
            _Authentication = authentication;
            _Confidentiality = confidentiality;
            _Integrity = integrity;
            _Availability = availability;
        }

        public string CVEId { get => _CVEId; set => _CVEId = value; }
        public string CWEId { get => _CWEId; set => _CWEId = value; }
        public string VulnerabilityType { get => _VulnerabilityType; set => _VulnerabilityType = value; }
        public string PublishDate { get => _PublishDate; set => _PublishDate = value; }
        public string UpdateDate { get => _UpdateDate; set => _UpdateDate = value; }
        public double Score { get => _Score; set => _Score = value; }
        public string ExploitExists { get => _ExploitExists; set => _ExploitExists = value; }
        public string Access { get => _Access; set => _Access = value; }
        public string Complexity { get => _Complexity; set => _Complexity = value; }
        public string Authentication { get => _Authentication; set => _Authentication = value; }
        public string Confidentiality { get => _Confidentiality; set => _Confidentiality = value; }
        public string Integrity { get => _Integrity; set => _Integrity = value; }
        public string Availability { get => _Availability; set => _Availability = value; }
        public string Description { get => _Description; set => _Description = value; }
    }
}
