using CVETool.DAL;
using CVETool.Entities;
using CVETool.Interfaces;
using CVETool.Utilities;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text;

namespace CVETool.BL
{
    public static class CVEManager
    {
        private static ICVEManager instance;

        public static ICVEManager GetInstance()
        {
            if (instance == null)
            {
                instance = new CVEManagerImpl();
            }
            return instance;
        }
    }

}
