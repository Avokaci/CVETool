using CVETool.BL;
using System;

namespace CVETool.UI
{
    public class Program
    {
        static void Main(string[] args)
        {
            var watch = System.Diagnostics.Stopwatch.StartNew();

            CVEManager manager = new CVEManager();
            manager.LoadJson();
            watch.Stop();
            TimeSpan timeSpan = watch.Elapsed;
            Console.WriteLine("Time: {0}h {1}m {2}s {3}ms", timeSpan.Hours, timeSpan.Minutes, timeSpan.Seconds, timeSpan.Milliseconds);


        }
    }
}
