using System;
using System.IO;

namespace CVETool.Utilities
{
    public class LogWriter
    {


        public void LogToConsoleProcessInfo(string logMessage)
        {
            Console.ForegroundColor = ConsoleColor.DarkGreen;
            Console.Write("\r\n" + $"{DateTime.Now.ToLongTimeString()} {DateTime.Now.ToLongDateString()}" + $"  : {logMessage}");

        }
        public void LogToConsoleObjectInfo(string logMessage)
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write("\r\n" + $"{DateTime.Now.ToLongTimeString()} {DateTime.Now.ToLongDateString()}" + $"  : {logMessage}");

        }
        public void LogToFile(string logMessage, TextWriter w)
        {
            w.Write("\r\n" + $"{DateTime.Now.ToLongTimeString()} {DateTime.Now.ToLongDateString()}" + $"  : {logMessage}");

        }

        public void DumpLog(StreamReader r)
        {
            string line;
            while ((line = r.ReadLine()) != null)
            {
                Console.WriteLine(line);
            }
        }
    }
}
