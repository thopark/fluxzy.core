﻿using System;
using System.IO;

namespace Echoes.H2.Cli
{
    public readonly struct GoAwayFrame : IBodyFrame
    {
        public uint LastStreamId { get; }

        public uint ErrorCode { get; }

        public int BodyLength => throw new NotImplementedException();

        public void Write(Stream stream)
        {
            throw new NotImplementedException();
        }
    }
}