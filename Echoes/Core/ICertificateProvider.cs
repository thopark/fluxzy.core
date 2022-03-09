﻿using System;
using System.Security.Cryptography.X509Certificates;

namespace Echoes.Core
{
    public interface ICertificateProvider : IDisposable
    {
        X509Certificate2 GetCertificate(string hostName);
    }
}