/*
 * Parcel Logistics Service
 *
 * No description provided (generated by Swagger Codegen https://github.com/swagger-api/swagger-codegen)
 *
 * OpenAPI spec version: 1.20.2
 * 
 * Generated by: https://github.com/swagger-api/swagger-codegen.git
 */
using System;
using System.Collections.Generic;
using Microsoft.AspNetCore.Mvc;
using Swashbuckle.AspNetCore.Annotations;
using Swashbuckle.AspNetCore.SwaggerGen;
using Newtonsoft.Json;
using System.ComponentModel.DataAnnotations;
using CVETool.WebAPI.Attributes;

using Microsoft.AspNetCore.Authorization;
using CVETool.WebAPI.Models;
using CVETool.Entities;
using CVETool.BL;
using CVETool.Interfaces;
using System.Text;

namespace CVETool.WebAPI.Controllers
{
    /// <summary>
    /// 
    /// </summary>
    [ApiController]
    public class CVEAPI : ControllerBase
    {
        ICVEManager manager = CVEManager.GetInstance();

        //Console App initialization only 
        //[HttpPost]
        //[Route("/autoInit")]
        //[ValidateModelState]
        //[SwaggerOperation("AutoInit")]
        //[SwaggerResponse(statusCode: 200, type: typeof(CVE), description: "")]
        //[SwaggerResponse(statusCode: 400, type: typeof(Error), description: "")]
        //public virtual IActionResult AutoInit()
        //{
        //    try
        //    {
        //        manager.AutoInit();
        //        return new ObjectResult("Auto initialization succesfull") { StatusCode = 200 };
        //    }
        //    catch (Exception)
        //    {
        //        return new ObjectResult("Error") { StatusCode = 400 };
        //    }
        //}

        //Console App initialization only 
        //[HttpPost]
        //[Route("/load")]
        //[ValidateModelState]
        //[SwaggerOperation("LoadJson")]
        //[SwaggerResponse(statusCode: 200, type: typeof(CVE), description: "")]
        //[SwaggerResponse(statusCode: 400, type: typeof(Error), description: "")]
        //public virtual IActionResult LoadJson()
        //{
        //    try
        //    {
        //        manager.LoadJson();
        //        return new ObjectResult("Files succesfully loaded") { StatusCode = 200 };
        //    }
        //    catch (Exception)
        //    {
        //        return new ObjectResult("Error") { StatusCode = 400 };
        //    }
        //}

        //Console App initialization only 
        //[HttpPost]
        //[Route("/create")]
        //[ValidateModelState]
        //[SwaggerOperation("CreateCVEs")]
        //[SwaggerResponse(statusCode: 200, type: typeof(CVE), description: "")]
        //[SwaggerResponse(statusCode: 400, type: typeof(Error), description: "")]
        //public virtual IActionResult CreateCVEs()
        //{
        //    try
        //    {           
        //        manager.CreateCVEs();
        //        return new ObjectResult("CVEs succesfully created") { StatusCode = 200 };           
        //    }
        //    catch (Exception)
        //    {
        //        return new ObjectResult("Error") { StatusCode = 400 };
        //    }
        //}

        //Console App initialization only 
        //[HttpPost]
        //[Route("/saveCVEsDB")]
        //[ValidateModelState]
        //[SwaggerOperation("saveCVEsDB")]
        //[SwaggerResponse(statusCode: 200, type: typeof(CVE), description: "")]
        //[SwaggerResponse(statusCode: 400, type: typeof(Error), description: "")]
        //public virtual IActionResult SaveCVEsDB()
        //{
        //    try
        //    {
        //        manager.SaveCVEsToDatabase();
        //        return new ObjectResult("CVEs succesfully created") { StatusCode = 200 };
        //    }
        //    catch (Exception)
        //    {
        //        return new ObjectResult("Error") { StatusCode = 400 };
        //    }
        //}

        [HttpGet]
        [Route("/cves")]
        [ValidateModelState]
        [SwaggerOperation("GetAllCVEs")]
        [SwaggerResponse(statusCode: 200, type: typeof(CVE), description: "")]
        [SwaggerResponse(statusCode: 400, type: typeof(Error), description: "")]
        public virtual IActionResult GetAllCVEs()
        {
            try
            {
                List<CVE> cveList = manager.GetAllCVEs();               
                return new ObjectResult(cveList) { StatusCode = 200 };
            }
            catch (Exception)
            {
                return new ObjectResult("Error") { StatusCode = 400 };
            }
        }

        // Not used
        //[HttpGet]
        //[Route("/cve/{cveId}")]
        //[ValidateModelState]
        //[SwaggerOperation("GetOneCVE")]
        //[SwaggerResponse(statusCode: 200, type: typeof(CVE), description: "")]
        //[SwaggerResponse(statusCode: 400, type: typeof(Error), description: "")]
        //public virtual IActionResult GetOneCVE([FromRoute][Required] string cveId)
        //{
        //    try
        //    {
        //        CVE foundCve = manager.GetSingleCVE(cveId);              
        //        return new ObjectResult(foundCve.ToString()) { StatusCode = 200 };

        //    }
        //    catch (Exception)
        //    {
        //        return new ObjectResult("Error") { StatusCode = 400 };
        //    }
        //}

        [HttpGet]
        [Route("/cves/filtered/{attribute}/{value}")]
        [ValidateModelState]
        [SwaggerOperation("GetAllFilteredCVEs")]
        [SwaggerResponse(statusCode: 200, type: typeof(CVE), description: "")]
        [SwaggerResponse(statusCode: 400, type: typeof(Error), description: "")]
        public virtual IActionResult GetAllFilteredCVEs([FromRoute][Required] string attribute, [FromRoute][Required] string value)
        {
            try
            {
                List<CVE> cveList = manager.GetAllFilteredCVEs(attribute,value);
                return new ObjectResult(cveList) { StatusCode = 200 };
            }
            catch (Exception)
            {
                return new ObjectResult("Error") { StatusCode = 400 };
            }
        }

        [HttpGet]
        [Route("/cves/filtered/year/{startYear}/range/{endYear}")]
        [ValidateModelState]
        [SwaggerOperation("GetAllYearRangeFilteredCVEs")]
        [SwaggerResponse(statusCode: 200, type: typeof(CVE), description: "")]
        [SwaggerResponse(statusCode: 400, type: typeof(Error), description: "")]
        public virtual IActionResult GetAllYearRangeFilteredCVEs([FromRoute][Required] string startYear, [FromRoute][Required] string endYear)
        {
            try
            {
                List<CVE> cveList = manager.GetAllYearRangeFilteredCVEs(startYear,endYear);
                return new ObjectResult(cveList) { StatusCode = 200 };
            }
            catch (Exception)
            {
                return new ObjectResult("Error") { StatusCode = 400 };
            }
        }

        [HttpGet]
        [Route("/cves/filtered/score/{startScore}/range/{endScore}")]
        [ValidateModelState]
        [SwaggerOperation("GetAllScoreRangeFilteredCVEs")]
        [SwaggerResponse(statusCode: 200, type: typeof(CVE), description: "")]
        [SwaggerResponse(statusCode: 400, type: typeof(Error), description: "")]
        public virtual IActionResult GetAllScoreRangeFilteredCVEs([FromRoute][Required] double startScore, [FromRoute][Required] double endScore)
        {
            try
            {
                List<CVE> cveList = manager.GetAllScoreRangeFilteredCVEs(startScore, endScore);
                return new ObjectResult(cveList) { StatusCode = 200 };
            }
            catch (Exception)
            {
                return new ObjectResult("Error") { StatusCode = 400 };
            }
        }

    }
}
