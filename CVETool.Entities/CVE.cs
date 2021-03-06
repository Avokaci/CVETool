using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Runtime.Serialization;
using System.Text;
using System.Threading.Tasks;

namespace CVETool.Entities
{
    [DataContract]
    public class CVE
    {
        [Required]
        private string _CVEId;
        [Required]
        private string _CWEId;
        [Required]
        private string _VulnerabilityType;
        [Required]
        private string _Description;
        [Required]
        private string _PublishDate;
        [Required]
        private string _UpdateDate;
        [Required]
        private double _Score;
        [Required]
        private string _SearchExploit;
        [Required]
        private string _Access;
        [Required]
        private string _Complexity;
        [Required]
        private string _Authentication;
        [Required]
        private string _Confidentiality;
        [Required]
        private string _Integrity;
        [Required]
        private string _Availability;

        public CVE(string cVEId, string cWEId, string vulnerabilityType, 
            string description, string publishDate, string updateDate, double score, 
            string searchExploit, string access, string complexity, 
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
            _SearchExploit = searchExploit;
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
        public string SearchExploit { get => _SearchExploit; set => _SearchExploit = value; }
        public string Access { get => _Access; set => _Access = value; }
        public string Complexity { get => _Complexity; set => _Complexity = value; }
        public string Authentication { get => _Authentication; set => _Authentication = value; }
        public string Confidentiality { get => _Confidentiality; set => _Confidentiality = value; }
        public string Integrity { get => _Integrity; set => _Integrity = value; }
        public string Availability { get => _Availability; set => _Availability = value; }
        public string Description { get => _Description; set => _Description = value; }

        public override string ToString()
        {
            var sb = new StringBuilder();
            sb.Append("  CVEId: ").Append(CVEId).Append("\n");
            sb.Append("  CWEId: ").Append(CWEId).Append("\n");
            sb.Append("  VulnerabilityType: ").Append(VulnerabilityType).Append("\n");
            sb.Append("  Description: ").Append(Description).Append("\n");
            sb.Append("  PublishDate: ").Append(PublishDate).Append("\n");
            sb.Append("  UpdateDate: ").Append(UpdateDate).Append("\n");
            sb.Append("  Score: ").Append(Score).Append("\n");
            sb.Append("  SearchExploit: ").Append(SearchExploit).Append("\n");
            sb.Append("  Access: ").Append(Access).Append("\n");
            sb.Append("  Complexity: ").Append(Complexity).Append("\n");
            sb.Append("  Authentication: ").Append(Authentication).Append("\n");
            sb.Append("  Confidentiality: ").Append(Confidentiality).Append("\n");
            sb.Append("  Integrity: ").Append(Integrity).Append("\n");
            sb.Append("  Availability: ").Append(Availability).Append("\n");
            return sb.ToString();

         
        }
        public string ToStringFlat()
        {
            var sb = new StringBuilder();
            sb.Append("  CVEId: ").Append(CVEId).Append("; ");
            sb.Append("  CWEId: ").Append(CWEId).Append("; ");
            sb.Append("  VulnerabilityType: ").Append(VulnerabilityType).Append("; ");
            sb.Append("  PublishDate: ").Append(PublishDate).Append("; ");
            sb.Append("  UpdateDate: ").Append(UpdateDate).Append("; ");
            sb.Append("  Score: ").Append(Score).Append("; ");
            sb.Append("  SearchExploit: ").Append(SearchExploit).Append("; ");
            sb.Append("  Access: ").Append(Access).Append("; ");
            sb.Append("  Complexity: ").Append(Complexity).Append("; ");
            sb.Append("  Authentication: ").Append(Authentication).Append("; ");
            sb.Append("  Confidentiality: ").Append(Confidentiality).Append("; ");
            sb.Append("  Integrity: ").Append(Integrity).Append("; ");
            sb.Append("  Availability: ").Append(Availability).Append("; ");
            sb.Append("  Description: ").Append(Description).Append("; ");
            return sb.ToString();
        }
    }
}
