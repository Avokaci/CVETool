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
            var elapsedMs = watch.ElapsedMilliseconds;
            Console.WriteLine(elapsedMs);

        }
    }
}
