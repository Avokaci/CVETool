using CVETool.BL;
using CVETool.Interfaces;
using CVETool.Utilities;
using Microsoft.Extensions.Logging;
using System;

namespace CVETool.UI
{
    public class Program
    {
      

        static void Main(string[] args)
        {


            var watch = System.Diagnostics.Stopwatch.StartNew();
            ICVEManager manager = CVEManager.GetInstance();
            manager.AutoInit();
            watch.Stop();
            TimeSpan timeSpan = watch.Elapsed;
            Console.WriteLine("Time: {0}h {1}m {2}s", timeSpan.Hours, timeSpan.Minutes, timeSpan.Seconds);


        }
    }
}
