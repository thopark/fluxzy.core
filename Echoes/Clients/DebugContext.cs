﻿using System;
using System.IO;

namespace Echoes.Clients
{
    public static class DebugContext
    {
        /// <summary>
        /// Reference for current debug sessions
        /// </summary>
        public static string ReferenceString { get; } = DateTime.Now.ToString("yyyyMMddHHmmss");

        /// <summary>
        /// Get the value whether network file dump is active. Can be modified by setting environment variable
        /// "Echoes_EnableNetworkFileDump"
        /// </summary>
        public static bool EnableNetworkFileDump { get; }

        /// <summary>
        /// Enable trace on H2 window updates 
        /// </summary>
        public static bool EnableWindowSizeTrace { get; }
        
        public static bool EnableDumpStackTraceOn502 { get; }
            = !string.IsNullOrWhiteSpace(Environment
                .GetEnvironmentVariable("EnableDumpStackTraceOn502"));


        public static bool InsertEchoesMetricsOnResponseHeader { get; }
            = !string.IsNullOrWhiteSpace(Environment
                .GetEnvironmentVariable("InsertEchoesMetricsOnResponseHeader"));


        /// <summary>
        /// When EnableNetworkFileDump is enable. Get the dump directory. Default value is "./raw".
        /// Can be modified by setting environment variable "Echoes_FileDumpDirectory" ; 
        /// 
        /// </summary>
        public static string NetworkFileDumpDirectory { get; }

        /// <summary>
        /// When EnableWindowSizeTrace is enabled, store the logs on this directory
        /// </summary>
        public static string WindowSizeTraceDumpDirectory { get; } = "trace";


        /// <summary>
        /// Incremental index of filedump 
        /// </summary>
        internal static int FileDumpIndex = 0;

        static DebugContext()
        {
            var fileDump = Environment
                .GetEnvironmentVariable("Echoes_EnableNetworkFileDump")?.Trim();

            EnableNetworkFileDump = string.Equals(fileDump, "true", StringComparison.OrdinalIgnoreCase)
                             || string.Equals(fileDump, "1", StringComparison.OrdinalIgnoreCase);


            var windowSizeTrace = Environment
                .GetEnvironmentVariable("Echoes_EnableWindowSizeTrace")?.Trim();

            EnableWindowSizeTrace = string.Equals(windowSizeTrace, "true", StringComparison.OrdinalIgnoreCase)
                                    || string.Equals(windowSizeTrace, "1", StringComparison.OrdinalIgnoreCase);

            NetworkFileDumpDirectory = Environment
                .GetEnvironmentVariable("Echoes_FileDumpDirectory")?.Trim() ?? "raw";
            
            if (EnableNetworkFileDump) 
                Directory.CreateDirectory(DebugContext.NetworkFileDumpDirectory);

            if (EnableWindowSizeTrace)
                Directory.CreateDirectory(DebugContext.WindowSizeTraceDumpDirectory);
        }
    }
}