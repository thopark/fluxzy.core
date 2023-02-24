﻿// // Copyright 2022 - Haga Rakotoharivelo
// 

using Org.BouncyCastle.Utilities.Encoders;
using System.Text;
// ReSharper disable InconsistentNaming

namespace Fluxzy.Bulk.BcCli
{
    public class NssLogWriter : IDisposable
    {
        public static readonly string CLIENT_TRAFFIC_SECRET_0 = "CLIENT_TRAFFIC_SECRET_0";
        public static readonly string SERVER_TRAFFIC_SECRET_0 = "SERVER_TRAFFIC_SECRET_0";
        public static readonly string CLIENT_HANDSHAKE_TRAFFIC_SECRET = "CLIENT_HANDSHAKE_TRAFFIC_SECRET";
        public static readonly string SERVER_HANDSHAKE_TRAFFIC_SECRET = "SERVER_HANDSHAKE_TRAFFIC_SECRET";
        public static readonly string EXPORTER_SECRET = "EXPORTER_SECRET";
        
        public static readonly string CLIENT_RANDOM = "CLIENT_RANDOM";

        private readonly Stream _stream;
        private readonly StreamWriter _streamWriter;

        public NssLogWriter(string fileName) : this(File.Create(fileName))
        {

        }
        
        public NssLogWriter(Stream stream)
        {
            _stream = stream;
            
            _streamWriter = new StreamWriter(stream, Encoding.UTF8) {
                NewLine = "\r\n",
                AutoFlush = true
            };

            _streamWriter.WriteLine("# This NSS Key log file was generated by Fluxzy");
        }

        public void Write(string key, byte[] clientRandom, byte[] secret)
        {
            _streamWriter.WriteLine($"{key} {Hex.ToHexString(clientRandom)} {Hex.ToHexString(secret)}");
        }

        
        public void Dispose()
        {
            _stream.Dispose();
        }
    }
}