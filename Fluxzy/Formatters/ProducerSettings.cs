﻿// Copyright © 2022 Haga Rakotoharivelo

namespace Fluxzy.Screeners
{
    public class ProducerSettings
    {
        public int MaxFormattableJsonLength { get; set; } = 1024 * 32;

        public int MaxFormattableXmlLength { get; set; } = 1024 * 32;
    }
}