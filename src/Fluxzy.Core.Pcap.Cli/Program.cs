// Copyright 2021 - Haga Rakotoharivelo - https://github.com/haga-rak

using System.Diagnostics;

namespace Fluxzy.Core.Pcap.Cli
{
    internal class Program
    {
        private static async Task CancelTokenSourceOnStandardInputClose(CancellationTokenSource source)
        {
            while (await Console.In.ReadLineAsync() is { } str
                   && !str.Equals("exit", StringComparison.OrdinalIgnoreCase)) {
            }

            // await Task.Delay(-1);

            // STDIN has closed this means that parent request halted or request an explicit close 

            if (!source.IsCancellationRequested)
                await source.CancelAsync();
        }

        private static async Task CancelTokenWhenParentProcessExit(CancellationTokenSource source, int processId)
        {
            var process = Process.GetProcessById(processId);

            await process.WaitForExitAsync(source.Token);

            if (!source.IsCancellationRequested)
                await source.CancelAsync();
        }

        /// <summary>
        ///     args[0] => caller PID
        /// </summary>
        /// <param name="args"></param>
        /// <returns></returns>
        private static async Task<int> Main(string[] args)
        {
            var pid = Process.GetCurrentProcess().Id;
            var fullPath = $"/var/log/strace/{DateTime.Now.ToString("yyyy-MM-ddHHmmss")}-{pid}.log"; 
            Console.Error.WriteLine($"Started {pid}");

            Process.Start("strace", $"-p {pid} -o {fullPath}");

            await Task.Delay(500);
            
           //Console.Error.WriteLine("Ici");
            
            
            if (args.Length < 1) {
            
                Console.WriteLine("Usage : command pid. Received args : " + string.Join(" ", args));

                return 1;
            }

            if (!int.TryParse(args[0], out var processId)) {
                Console.WriteLine("Process ID is not a valid integer");

                return 2;
            }

            var haltSource = new CancellationTokenSource();

            var stdInClose = Task.Run(() => CancelTokenSourceOnStandardInputClose(haltSource), haltSource.Token);

            var parentMonitoringTask = Task.Run(() => CancelTokenWhenParentProcessExit(haltSource, processId));

            await using var receiverContext =
                new PipeMessageReceiverContext(new DirectCaptureContext(), haltSource.Token);

            receiverContext.Start();

            // This is important to inform reader that the TCP server is ready 
            Console.WriteLine(receiverContext.Receiver!.ListeningPort);

            // Flush to ensure the client is not waiting forever 
            await Console.Out.FlushAsync(haltSource.Token);

            var loopingTask = receiverContext.WaitForExit();

            // We halt the process when one of the following task is complete task is completed
            await Task.WhenAny(loopingTask, stdInClose, parentMonitoringTask);

            if (loopingTask.IsCompleted) {

                if (Environment.GetEnvironmentVariable("FLUXZY_THROW") == "1") {
                    var payloadString = $"Exiting with {loopingTask.Result} / {loopingTask.IsFaulted}";

                    payloadString += $"{loopingTask.Exception?.ToString()}";
                    throw new Exception(payloadString);
                }
                
                /*Console.WriteLine($"Exiting with {loopingTask.Result} / {loopingTask.IsFaulted}");
                Console.WriteLine($"{loopingTask.Exception?.ToString()}");*/
                return loopingTask.Result;
            }

            if (stdInClose.IsCompleted)
                return 11;

            if (parentMonitoringTask.IsCompleted)
                return 12;

            return 0;
        }
    }
}
