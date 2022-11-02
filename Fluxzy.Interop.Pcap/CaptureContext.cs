﻿// Copyright © 2022 Haga Rakotoharivelo

using System.Net;
using System.Net.NetworkInformation;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;

namespace Fluxzy.Interop.Pcap
{
    public class CaptureContext : IAsyncDisposable
    {
        private readonly PcapDevice _captureDevice;

        private bool _halted;
        private readonly PhysicalAddress _physicalLocalAddress;
        private readonly PacketQueue _packetQueue = new();
        private bool _disposed;

        public CaptureContext(IPAddress?  localAddress = null)
        {
            var localAddress1 = localAddress ?? IpUtility.GetDefaultRouteV4Address();

            //targetItem
            _captureDevice = CaptureDeviceList.Instance.OfType<PcapDevice>()
                                              .Where(l => !l.IsLoopback())
                                              .OrderByDescending(l => l.IsUp())
                                              .ThenByDescending(l => l.IsRunning())
                                              .ThenByDescending(l => l.IsConnected())
                                              .ThenByDescending(d => d.Interface.Addresses.Any(
                                                  a => Equals(a.Addr.ipAddress, localAddress1)))
                                              .ThenByDescending(d => d.Interface.GatewayAddresses.Any(g => !g.IsIPv6LinkLocal))
                                              .First();
            
            _physicalLocalAddress = _captureDevice.MacAddress;

            Start();
        }

        public void Include(IPAddress remoteAddress, int remotePort)
        {
            _packetQueue.Include(remoteAddress, remotePort);
        }

        public IConnectionSubscription Subscribe(string outFileName, IPAddress remoteAddress, int remotePort, int localPort)
        {
            return _packetQueue.Subscribe(outFileName, remoteAddress, remotePort, localPort);
        } 

        public void Unsubscribe(IConnectionSubscription subscription)
        {
            _packetQueue.Unsubscribe(subscription);
        } 

        private void Start()
        {
            _captureDevice.Open();
            _captureDevice.Filter = $"tcp";
            _captureDevice.OnPacketArrival += OnCaptureDeviceOnOnPacketArrival;
            _captureDevice.StartCapture();
        }

        public void Stop()
        {
            if (_halted)
                return;

            _halted = true;

            _captureDevice.OnPacketArrival -= OnCaptureDeviceOnOnPacketArrival;

            if (_captureDevice.Opened)
                _captureDevice.StopCapture();
        }

        private void OnCaptureDeviceOnOnPacketArrival(object sender, PacketCapture capture)
        {
            var rawPacket = capture.GetPacket();
            var ethernetPacket = (EthernetPacket) rawPacket.GetPacket();

            // SE REFERER à la date
            
            _packetQueue.Enqueue(rawPacket, ethernetPacket, _physicalLocalAddress);
        }
        

        public async ValueTask DisposeAsync()
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;

            Stop();

            _captureDevice.Dispose();
            await _packetQueue.DisposeAsync();
        }
    }


    public static class FlagInterpreter
    {
//         /*
//          * #define PCAP_IF_LOOPBACK				0x00000001	/* interface is loopback */
// #define PCAP_IF_UP					0x00000002	/* interface is up */
// #define PCAP_IF_RUNNING					0x00000004	/* interface is running */
// #define PCAP_IF_WIRELESS				0x00000008	/* interface is wireless (*NOT* necessarily Wi-Fi!) */
// #define PCAP_IF_CONNECTION_STATUS			0x00000030	/* connection status: */
// #define PCAP_IF_CONNECTION_STATUS_UNKNOWN		0x00000000	/* unknown */
// #define PCAP_IF_CONNECTION_STATUS_CONNECTED		0x00000010	/* connected */
// #define PCAP_IF_CONNECTION_STATUS_DISCONNECTED		0x00000020	/* disconnected */
// #define PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE	0x00000030	/* not applicable */
//          */
        
        public static bool IsUp(this PcapDevice device)
        {
            return (((LibPcapLiveDevice) device).Flags & 0x00000002) > 0; 
        }
        public static bool IsConnected(this PcapDevice device)
        {
            return (((LibPcapLiveDevice) device).Flags & 0x00000010) > 0; 
        }
        public static bool IsRunning(this PcapDevice device)
        {
            return (((LibPcapLiveDevice) device).Flags & 0x00000004) > 0; 
        }
        
        public static bool IsLoopback(this PcapDevice device)
        {
            return (((LibPcapLiveDevice) device).Flags & 0x00000001) > 0; 
        }
    }
}