﻿/*
 * Copyright (c) 2023, Lawrence Livermore National Security, LLC.
 * Produced at the Lawrence Livermore National Laboratory.
 * All rights reserved.
 */



using System;
using System.Text;
using System.IO;
using System.Reflection;
using System.Collections.Concurrent;
using System.ComponentModel;

namespace FileEntropy
{
    public enum Status
    {
        OK, Important, Warning, Critical
    }


    public enum LogType
    {
        Append, Overwrite, Archive
    }

    /// <summary>
    /// When to log this message
    /// </summary>
    public enum LogLevel
    {
        Always = 1,
        Debug = 2
    }

    /// <summary>
    /// a simple logging class
    /// </summary>
    public sealed class WintapLogger
    {
        private static readonly WintapLogger log = new WintapLogger();

        private string logName;
        private LogType logType = LogType.Overwrite;
        private LogLevel verbosity;
        //private string logDir = Environment.GetEnvironmentVariable("temp");
        private string logDir = Environment.GetEnvironmentVariable("PROGRAMDATA") + "\\Wintap\\Logs";
        private string userName;
        private string logPath;
        DateTime startTime;
        DateTime endTime;
        private StreamWriter logWriter;
        private int maxSize = 3000000;  //default to 3MB file
        private System.TimeSpan runTime;
        decimal elapsedTime;
        private string statusMsg;
        private Status status;
        private string author = "not set";
        private string codeVersion;
        private string clientName = Environment.GetEnvironmentVariable("COMPUTERNAME");
        private ConcurrentQueue<LogEntry> pendingEntries;
        private BackgroundWorker loggingThread;
        private bool logIsOpen;


        private WintapLogger()
        {
            this.LogType = LogType.Overwrite;
            this.MaxSize = 3000000;
            this.Verbosity = LogLevel.Debug;
            this.logDir = Environment.GetEnvironmentVariable("PROGRAMDATA") + "\\Wintap\\Logs";
            this.LogName = "FileEntropy";
            this.Init();

            // Get the name of the calling process
            Assembly exeName = Assembly.GetCallingAssembly();
            string[] logNameArray = exeName.FullName.Split(new Char[] { ',' });
            logName = logNameArray[0].ToString();
            verbosity = LogLevel.Debug;
            codeVersion = exeName.GetName().Version.ToString();
            pendingEntries = new ConcurrentQueue<LogEntry>();
            logIsOpen = true;
            loggingThread = new BackgroundWorker();
            loggingThread.DoWork += new DoWorkEventHandler(loggingThread_DoWork);
            loggingThread.RunWorkerAsync();
        }

        public static WintapLogger Log
        {
            get
            {
                return log;
            }
        }


        public void Init()
        {
            DirectoryInfo logDirInfo = new DirectoryInfo(logDir);
            if (!logDirInfo.Exists)
            {
                if (!logDirInfo.Parent.Exists)
                {
                    logDirInfo.Parent.Create();
                }
                logDirInfo.Create();

            }

            status = Status.OK;
            statusMsg = "n/a";
            try
            {
                userName = Environment.GetEnvironmentVariable("username");
            }
            catch
            {
                userName = "N/A";
            }

            if (!logDir.Trim().EndsWith("\\"))
            {
                logDir = logDir.Insert(logDir.Length, "\\");
            }
            StringBuilder pathBld = new StringBuilder();
            pathBld.Append(logDir);
            pathBld.Append(logName);
            pathBld.Append(".log");
            logPath = pathBld.ToString();
            startTime = DateTime.Now;
            switch (LogType)
            {
                case LogType.Overwrite:
                    try
                    {
                        if (File.Exists(logPath))
                        {
                            File.Delete(logPath);
                        }
                        FileStream fs = File.Open(logPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.ReadWrite);
                        logWriter = new StreamWriter(fs);
                        logWriter.WriteLine("Start of log for: " + logName + ", Version: " + codeVersion);
                        logWriter.WriteLine("Start time: " + DateTime.Now.ToLongTimeString() + " " + DateTime.Now.ToLongDateString());
                        logWriter.WriteLine("**************************************");
                        logWriter.Flush();
                    }
                    catch
                    {
                    }
                    break;
                case LogType.Append:
                    try
                    {
                        FileStream fsAppend = File.Open(logPath, FileMode.Append, FileAccess.Write, FileShare.ReadWrite);
                        logWriter = new StreamWriter(fsAppend);
                        logWriter.WriteLine("Start of log for: " + logName + ", Version: " + codeVersion);
                        logWriter.WriteLine("Start time: " + DateTime.Now.ToLongTimeString() + " " + DateTime.Now.ToLongDateString());
                        logWriter.WriteLine("**************************************");
                    }
                    catch { }
                    break;
                case LogType.Archive:
                    if (File.Exists(logPath))
                    {
                        StringBuilder archName = new StringBuilder();
                        archName.Append(logPath);
                        // only keep 365 logs in archive
                        archName.Append(DateTime.Now.Date.DayOfYear);
                        archName.Append(".log");
                        try
                        {
                            if (File.Exists(archName.ToString()))
                            {
                                File.Delete(archName.ToString());
                            }
                            File.Move(logPath, archName.ToString());
                        }
                        catch
                        {
                        }
                    }
                    try
                    {
                        FileStream fsArchive = File.Open(logPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.ReadWrite);
                        logWriter = new StreamWriter(fsArchive);
                        logWriter.WriteLine("Start of log for: " + logName + ", Version: " + codeVersion);
                        logWriter.WriteLine("Start time: " + DateTime.Now.ToLongTimeString() + " " + DateTime.Now.ToLongDateString());
                        logWriter.WriteLine("**************************************");
                    }
                    catch
                    {
                    }
                    break;
            }
        }

        public void Append(string entry, LogLevel targetVerbosity)
        {
            LogEntry le = new LogEntry();
            le.Entry = entry;
            le.Time = DateTime.Now;
            le.Level = targetVerbosity;
            pendingEntries.Enqueue(le);
        }

        void loggingThread_DoWork(object sender, DoWorkEventArgs e)
        {
            while (logIsOpen)
            {
                int entryCount = pendingEntries.Count;
                for (int i = 0; i < entryCount; i++)
                {
                    LogEntry entry;
                    pendingEntries.TryDequeue(out entry);
                    if ((int)this.Verbosity >= (int)entry.Level)
                    {
                        FileInfo logInfo = new FileInfo(logPath);
                        if (logInfo.Length > maxSize)
                        {
                            try
                            {
                                logWriter.Close();
                                File.Delete(logPath);
                                FileStream fs = File.Open(logPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.ReadWrite);
                                logWriter = new StreamWriter(fs);
                                logWriter.WriteLine("LOG TRUNCATION HAS OCCURRED!!!");
                                logWriter.WriteLine("Continuation of log for: " + logName);
                                logWriter.WriteLine("Resume Start time: " + DateTime.Now.ToLongTimeString() + " " + DateTime.Now.ToLongDateString());
                                logWriter.WriteLine("**************************************");
                            }
                            catch
                            {
                            }
                        }
                        try
                        {
                            logWriter.WriteLine(entry.Time + " >>   " + entry.Entry);
                            logWriter.Flush();
                        }
                        catch
                        {
                        }
                    }
                }
                System.Threading.Thread.Sleep(200);
            }
        }

        public void Close()
        {
            System.Threading.Thread.Sleep(1000);  // allow time for queue to drain
            endTime = DateTime.Now;
            logIsOpen = false;
            try
            {
                logWriter.WriteLine("**************************************");
                logWriter.WriteLine("End of log for: " + logName);
                logWriter.WriteLine("End time: " + DateTime.Now.ToLongTimeString() + " " + DateTime.Now.ToLongDateString());
                runTime = endTime.Subtract(startTime);
                logWriter.WriteLine("Program Runtime: " + runTime.ToString());
                logWriter.Flush();
                string mils = runTime.Milliseconds.ToString();
                int secs = runTime.Seconds;
                int mins = runTime.Minutes;
                int hrs = runTime.Hours;
                int minsInSecs = mins * 60;
                int hrsInSecs = hrs * 60 * 60;
                int totalSecs = hrsInSecs + minsInSecs + secs;
                elapsedTime = System.Convert.ToDecimal(totalSecs.ToString() + "." + mils);
                logWriter.WriteLine("Runtime in seconds: " + elapsedTime.ToString());
                logWriter.Flush();
                logWriter.WriteLine("END OF LOG");
                logWriter.Close();
            }
            catch (Exception ex)
            {
                logWriter.WriteLine("ERROR: " + ex.Message);
                logWriter.Flush();
            }
        }

        /// <summary>
        /// Path to directory that will hold this log file. Default is %temp%.  Set BEFORE calling Init().
        /// <example>Example: c:\\Windows\\Temp </example>
        /// </summary>
        public string LogDir
        {
            get
            {
                return logDir;
            }
            set
            {
                DirectoryInfo dirTest = new DirectoryInfo(value);
                if (!dirTest.Exists)
                {
                    Exception pathException = new LogPathException("Log directory not found: " + value);
                    throw new LogPathException(pathException.Message);
                }
                else
                {
                    logDir = value;
                }
            }

        }

        /// <summary>
        /// SUPPORTED TYPES: Overwrite, Append, or Archive
        /// </summary>
        public LogType LogType
        {
            get
            {
                return logType;
            }
            set
            {
                logType = value;
            }
        }

        /// <summary>
        /// What level of messages should be written by this instance of Logit. Critical = least verbose, errors only. Warning = Critical + warning messages. Informational = All messsages, most verbose.
        /// </summary>
        public LogLevel Verbosity
        {
            get
            {
                return verbosity;
            }
            set
            {
                verbosity = value;
            }
        }

        /// <summary>
        /// Maximum byte size of the log before truncation, Default: 3MB
        /// </summary>
        public int MaxSize
        {
            get
            {
                return maxSize;
            }
            set
            {
                maxSize = value;
            }
        }

        /// <summary>
        /// Describes the error condition of your app.
        /// </summary>
        public Status Status
        {
            get
            {
                return status;
            }
            set
            {
                status = value;
            }
        }

        /// <summary>
        /// If you set Status to Error, then use this text message to describe the error. The 
        /// text entered here gets sent to web reporting along with there Error type.  Max 255 chars.
        /// </summary>
        public string StatusMsg
        {
            get
            {
                return statusMsg;
            }
            set
            {
                statusMsg = value;
            }
        }

        /// <summary>
        /// Name of the person who wrote it.
        /// </summary>
        public string Author
        {
            get
            {
                return author;
            }
            set
            {
                author = value;
            }
        }

        /// <summary>
        /// Name of Log file to create. 
        /// <BR></BR>
        /// <example>Example: MyWebService</example>
        /// </summary>
        public string LogName
        {
            get
            {
                return logName;
            }
            set
            {
                logName = value;
            }
        }


        public DateTime StartTime
        {
            get
            {
                return startTime;
            }
            set
            {
                startTime = value;
            }
        }


        public DateTime EndTime
        {
            get
            {
                return endTime;
            }
            set
            {
                endTime = value;
            }
        }

        /// <summary>
        /// Time in seconds of the execution time of the program
        /// </summary>
        public decimal ElapsedTime
        {
            get
            {
                return elapsedTime;
            }
            set
            {
                elapsedTime = value;
            }
        }

        /// <summary>
        /// Name of the computer that ran it
        /// </summary>
        public string ClientName
        {
            get
            {
                return clientName;
            }
            set
            {
                clientName = value;
            }
        }

        /// <summary>
        /// Name of the currently logged in user during execution
        /// <example></example>
        /// </summary>
        public string UserName
        {
            get
            {
                return userName;
            }
            set
            {
                userName = value;
            }
        }

        /// <summary>
        /// Version of your program. Read-Only.
        /// <example>2.0.1978.2142</example>
        /// </summary>
        public string CodeVersion
        {
            get
            {
                return codeVersion;
            }
        }
    }

    class LogTypeException : ApplicationException
    {
        public LogTypeException(string message)
            : base(message)
        {
        }
    }

    class LogPathException : ApplicationException
    {
        public LogPathException(string message)
            : base(message)
        {
        }
    }

    class LogEntry
    {
        private DateTime time;
        public DateTime Time
        {
            get { return time; }
            set { time = value; }
        }

        private string entry;
        public string Entry
        {
            get { return entry; }
            set { entry = value; }
        }

        private LogLevel level;
        public LogLevel Level
        {
            get { return level; }
            set { level = value; }
        }
    }
}
