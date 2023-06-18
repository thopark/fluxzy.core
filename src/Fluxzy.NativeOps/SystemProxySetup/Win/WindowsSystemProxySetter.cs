// Copyright 2021 - Haga Rakotoharivelo - https://github.com/haga-rak

using System.Runtime.Versioning;
using System.Threading.Tasks;
using Fluxzy.Core.Proxy;

namespace Fluxzy.NativeOps.SystemProxySetup.Win
{
    [SupportedOSPlatform("windows")]
    internal class WindowsSystemProxySetter : ISystemProxySetter
    {
        public Task ApplySetting(SystemProxySetting value)
        {
            WindowsProxyHelper.SetProxySetting(value);
            return Task.CompletedTask;
        }

        public Task<SystemProxySetting> ReadSetting()
        {
            return Task.FromResult(WindowsProxyHelper.GetSetting());
        }
    }
}
