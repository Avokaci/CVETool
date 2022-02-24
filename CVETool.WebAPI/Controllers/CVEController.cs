﻿/*
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

namespace CVETool.WebAPI.Controllers
{
    /// <summary>
    /// 
    /// </summary>
    [ApiController]
    public class CVEAPI : ControllerBase
    {
        CVEManager _manager = new CVEManager();

        string[] importedFiles { get; set; }

      
        [HttpPost]
        [Route("/autoInit")]
        [ValidateModelState]
        [SwaggerOperation("AutoInit")]
        [SwaggerResponse(statusCode: 200, type: typeof(CVE), description: "")]
        [SwaggerResponse(statusCode: 400, type: typeof(Error), description: "")]
        public virtual IActionResult AutoInit()
        {
            try
            {
                _manager.AutoInit();
                return new ObjectResult("Auto initialization succesfull") { StatusCode = 200 };
            }
            catch (Exception)
            {
                return new ObjectResult("Error") { StatusCode = 400 };
            }
        }

        [HttpPost]
        [Route("/load")]
        [ValidateModelState]
        [SwaggerOperation("LoadJson")]
        [SwaggerResponse(statusCode: 200, type: typeof(CVE), description: "")]
        [SwaggerResponse(statusCode: 400, type: typeof(Error), description: "")]
        public virtual IActionResult LoadJson()
        {
            try
            {
                importedFiles = _manager.LoadJson();
                return new ObjectResult("Files succesfully loaded") { StatusCode = 200 };
            }
            catch (Exception)
            {
                return new ObjectResult("Error") { StatusCode = 400 };
            }
        }


        [HttpPost]
        [Route("/create")]
        [ValidateModelState]
        [SwaggerOperation("CreateCVEs")]
        [SwaggerResponse(statusCode: 200, type: typeof(CVE), description: "")]
        [SwaggerResponse(statusCode: 400, type: typeof(Error), description: "")]
        public virtual IActionResult CreateCVEs()
        {
            try
            {
             
                //_manager.CreateCVEs();
                int i = _manager.CVEs.Count;

                return new ObjectResult("CVEs succesfully created") { StatusCode = 200 };
             

            }
            catch (Exception)
            {
                return new ObjectResult("Error") { StatusCode = 400 };
            }
        }

        [HttpPost]
        [Route("/saveCVEsDB")]
        [ValidateModelState]
        [SwaggerOperation("saveCVEsDB")]
        [SwaggerResponse(statusCode: 200, type: typeof(CVE), description: "")]
        [SwaggerResponse(statusCode: 400, type: typeof(Error), description: "")]
        public virtual IActionResult SaveCVEsDB()
        {
            try
            {
                _manager.SaveCVEsToDatabase();
                return new ObjectResult("CVEs succesfully created") { StatusCode = 200 };
            }
            catch (Exception)
            {
                return new ObjectResult("Error") { StatusCode = 400 };
            }
        }

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
                return new ObjectResult("Auto initialization succesfull") { StatusCode = 200 };

            }
            catch (Exception)
            {
                return new ObjectResult("Error") { StatusCode = 400 };
            }
        }


        [HttpGet]
        [Route("/cve/{cveId}")]
        [ValidateModelState]
        [SwaggerOperation("GetOneCVE")]
        [SwaggerResponse(statusCode: 200, type: typeof(CVE), description: "")]
        [SwaggerResponse(statusCode: 400, type: typeof(Error), description: "")]
        public virtual IActionResult GetOneCVE([FromRoute][Required] string cveId)
        {
            try
            {
                return new ObjectResult("Auto initialization succesfull") { StatusCode = 200 };

            }
            catch (Exception)
            {
                return new ObjectResult("Error") { StatusCode = 400 };
            }
        }


    }
}
