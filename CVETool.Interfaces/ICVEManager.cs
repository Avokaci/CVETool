using CVETool.Entities;
using System;

namespace CVETool.Interfaces
{
    public interface ICVEManager
    {
        public void LoadJson();
        public void CVEInit(JSONImport import);
    }
}
