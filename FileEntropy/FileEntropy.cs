/*
 * Copyright (c) 2023, Lawrence Livermore National Security, LLC.
 * Produced at the Lawrence Livermore National Laboratory.
 * All rights reserved.
 */


using gov.llnl.wintap;
using gov.llnl.wintap.collect.models;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.ComponentModel.Composition;
using System.Diagnostics.Tracing;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static gov.llnl.wintap.Interfaces;

namespace FileEntropy
{
    [Export(typeof(IQuery))]
    [Export(typeof(IProvide))]
    [ExportMetadata("Name", "FileEntropy")]
    [ExportMetadata("Description", "File entropy collector plugin")]
    public class FileEntropy : IQuery, IProvide
    {
        private static readonly Random getrandom = new Random();
        public event EventHandler<ProviderEventArgs> Events;

        public void Process(QueryResult result)
        {
            WintapLogger.Log.Append("new FileEntropy event processing started", LogLevel.Debug);

            string filePath = result.EventDetails.Where(r => r.Key == "FilePath").FirstOrDefault().Value;
            string eventTime = result.EventDetails.Where(r => r.Key == "EventTime").FirstOrDefault().Value;
            int pid = Convert.ToInt32(result.EventDetails.Where(r => r.Key == "PID").FirstOrDefault().Value);
            try
            {
                if (defeatPath(filePath))
                {
                    return;
                }

                int numBytes = 2048;
                EntropyHelper entropyHelper = ReadFileBytes(filePath, numBytes);
                byte[] buffy = entropyHelper.Buffer;
                FileInfo fi = new FileInfo(filePath);
                long fileSize = fi.Length;

                Double entropy = -1.0;
                if (buffy != null)
                {
                    entropy = CalculateEntropy(buffy);
                    if (entropy > -1.0)
                    {
                        WintapLogger.Log.Append("Creating WintapMessage for FileEntropy event", LogLevel.Debug);
                        WintapMessage.GenericMessageObject analyticEvent = new WintapMessage.GenericMessageObject();
                        analyticEvent.Provider = "Plugin";
                        analyticEvent.EventName = "OnClose";
                        analyticEvent.PID = pid;
                        EntropyResult er = new EntropyResult() { Entropy = entropy, Path = filePath, FileSize = entropyHelper.FileSize, StartOffSet = entropyHelper.StartOffSet };
                        analyticEvent.Payload = JsonConvert.SerializeObject(er);
                        Events.Invoke(this, new ProviderEventArgs() { GenericEvent = analyticEvent, Name = "FileEntropy" });
                        WintapLogger.Log.Append("IProvide event fired for entropy event: " + filePath, LogLevel.Debug);
                    }
                }
            }
            catch (Exception ex)
            {
                WintapLogger.Log.Append("Could not compute entropy. exception: " + ex.Message + " on file: " + filePath, LogLevel.Always);
            }
            WintapLogger.Log.Append("new FileEntropy event processing finished. " + filePath, LogLevel.Debug);
        }

        public void RaiseEvent()
        {
            // nothing
        }

        public List<EventQuery> Startup()
        {
            WintapLogger.Log.Append("FileEntropy plugin is starting. ", LogLevel.Always);
            List<EventQuery> queries = new List<EventQuery>();
            EventQuery firstQuery = new EventQuery();
            firstQuery.Name = "FileEntropy";
            string sql = "SELECT FileWrite.FileActivity.Path as FilePath, FileWrite.PID as PID, FileClose.EventTime as EventTime FROM pattern @SuppressOverlappingMatches [every FileWrite=WintapMessage(MessageType='File'AND ActivityType='WRITE' AND FileActivity.BytesRequested > 0)->FileClose=WintapMessage(MessageType='File' AND ActivityType='CLOSE' AND WintapMessage.PID=FileWrite.PID AND FileWrite.FileActivity.Path = FileActivity.Path) where timer:within(5 min)]";
            firstQuery.Query = sql;
            queries.Add(firstQuery);
            WintapLogger.Log.Append("FileEntropy plugin start up completed!", LogLevel.Always);
            return queries;
        }

        void IProvide.Startup()
        {
            // nothing
        }


        // Logic for defeating certain paths
        public Boolean defeatPath(String filePath)
        {
            if (filePath.Contains("c:\\$logfile") || filePath.Contains("wintap"))
            {
                return true;
            }
            return false;
        }

        static double CalculateEntropy(byte[] bytes)
        {
            int range = byte.MaxValue + 1;  // 0 -> 256
            double entropy = -1;  // -1 for errors in imput
            if (null == bytes || 0 >= bytes.Length)
            {
                return entropy;
            }
            entropy++;

            long[] frequencies = new long[range];
            foreach (byte value in bytes)
            {
                frequencies[value]++;
            }

            foreach (long count in frequencies)
            {
                if (0 != count)
                {
                    double probability = (double)count / bytes.LongLength;
                    entropy += probability * Math.Log(1 / probability, 2);
                }
            }

            return entropy;
        }

        private EntropyHelper ReadFileBytes(String filePath, int numBytes)
        {
            EntropyHelper entropyHelper = new EntropyHelper() { FilePath = filePath };
            FileInfo fi = new FileInfo(filePath);
            long fileSize = fi.Length;
            entropyHelper.FileSize = fileSize;

            // File too small for buffer size
            if (fileSize < numBytes)
            {
                return null;
            }

            // So, we want to read 'numBytes' out of random location in the file, not just start
            // Calculate the last possible starting byte offset
            int lastPos = (int)(fileSize - numBytes);
            if (lastPos < 0)
            {
                return null;
            }

            // Pick a random int between 0 and that lastPos offset
            long startOffset = GetRandomNumber(0, lastPos);
            entropyHelper.StartOffSet = startOffset;
            int offsetInTargetArray = 0;  // always write to the beginning of bytes_read
            entropyHelper.Buffer = new byte[numBytes];
            try
            {
                using (System.IO.FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read))
                {
                    fs.Seek(startOffset, SeekOrigin.Begin);
                    var bytes_read = fs.Read(entropyHelper.Buffer, offsetInTargetArray, entropyHelper.Buffer.Length);
                    fs.Close();

                    if (bytes_read != entropyHelper.Buffer.Length)  // not enough bytes avail in file
                    {
                        return null;
                    }
                }
            }
            catch (System.UnauthorizedAccessException ex)
            {
                return null;
            }
            return entropyHelper;
        }

        public static int GetRandomNumber(int min, int max)
        {
            lock (getrandom) // synchronize
            {
                return getrandom.Next(min, max);
            }
        }

        public void Shutdown()
        {
            WintapLogger.Log.Append("Shutting down", LogLevel.Always);
            WintapLogger.Log.Close();
        }
    }

    internal class EntropyHelper
    {
        internal string FilePath { get; set; }
        internal long StartOffSet { get; set; }
        internal byte[] Buffer { get; set; }
        internal long FileSize { get; set; }
    }

    public class EntropyResult
    {
        public double Entropy { get; set; }
        public string Path { get; set; }
        public long FileSize { get; set; }
        public long StartOffSet { get; set; }
    }
}
