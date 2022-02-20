using CVETool.BL;
using System;

namespace CVETool.UI
{
    public class Program
    {
        static void Main(string[] args)
        {
            CVEManager manager = new CVEManager();
            manager.LoadJson();

        }
    }
}
