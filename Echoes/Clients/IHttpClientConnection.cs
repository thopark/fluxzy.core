﻿// Copyright © 2021 Haga Rakotoharivelo

using System;
using System.Threading;
using System.Threading.Tasks;

namespace Echoes
{
    /// <summary>
    /// Represents a connection pool to the same authority, using the same .
    /// </summary>
    public interface IHttpConnectionPool : IAsyncDisposable, IDisposable
    {
        Authority Authority { get; }

        bool Complete { get; }
        
        Task Init();

        Task<bool> CheckAlive();
        
        ValueTask Send(Exchange exchange, ILocalLink localLink, CancellationToken cancellationToken = default);
    }
}