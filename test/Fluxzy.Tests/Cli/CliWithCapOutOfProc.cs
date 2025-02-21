using System.Collections.Generic;
using System.Threading.Tasks;
using Xunit;

namespace Fluxzy.Tests.Cli
{    
    [Collection("RUNS_RAW_CAPTURE")]
    public class CliWithCapOutOfProc : CliTestBase
    {
        public static IEnumerable<object[]> GetSingleRequestParametersNoDecrypt {
            get
            {
                var protocols = new[] { "http11", "http11-bc", "plainhttp11", "http2", "http2-bc" };
                var withPcapStatus = new[] { CaptureType.PcapOutOfProc };
                var directoryParams = new[] { false, true };
                var withSimpleRules = new[] { false, true };

                foreach (var protocol in protocols)
                foreach (var withPcap in withPcapStatus)
                foreach (var directoryParam in directoryParams)
                foreach (var withSimpleRule in withSimpleRules) {
                    yield return new object[] { protocol, withPcap, directoryParam, withSimpleRule };
                }
            }
        }

        [Theory]
        [MemberData(nameof(GetSingleRequestParametersNoDecrypt))]
        public async Task Run(string proto, CaptureType rawCap, bool @out, bool rule)
        {
            await base.Run_Cli_Output(proto, rawCap, @out, rule);
        }
    }
}