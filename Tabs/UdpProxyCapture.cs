using System;
using HytaleSecurityTester.Core;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

public class UdpProxyCapture
{
    private readonly TestLog _log;
    private readonly PacketCapture _capture;

    private UdpClient? _listener;
    private UdpClient? _server;
    private CancellationTokenSource? _cts;

    private IPEndPoint? _serverEp;
    private IPEndPoint? _clientEp;

    public UdpProxyCapture(TestLog log, PacketCapture capture)
    {
        _log = log;
        _capture = capture;
    }

    public void Start(string listenIp, int listenPort, string serverIp, int serverPort)
    {
        _cts = new CancellationTokenSource();

        _listener = new UdpClient(new IPEndPoint(IPAddress.Parse(listenIp), listenPort));
        _server = new UdpClient();
        _serverEp = new IPEndPoint(IPAddress.Parse(serverIp), serverPort);

        Task.Run(() => ClientLoop(_cts.Token));
        Task.Run(() => ServerLoop(_cts.Token));
    }

    public void Stop()
    {
        _cts?.Cancel();
        _listener?.Close();
        _server?.Close();
    }

    private async Task ClientLoop(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            var res = await _listener!.ReceiveAsync(ct);
            _clientEp = res.RemoteEndPoint;

            await _server!.SendAsync(res.Buffer, res.Buffer.Length, _serverEp!);
            AddPacket(res.Buffer, PacketDirection.ClientToServer);
        }
    }

    private async Task ServerLoop(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            var res = await _server!.ReceiveAsync(ct);
            if (_clientEp != null)
                await _listener!.SendAsync(res.Buffer, res.Buffer.Length, _clientEp);

            AddPacket(res.Buffer, PacketDirection.ServerToClient);
        }
    }

    private void AddPacket(byte[] data, PacketDirection dir)
    {
        _capture.AddPacketExternal(new CapturedPacket
        {
            Timestamp = DateTime.Now,
            Direction = dir,
            RawBytes = data,
            HexString = PacketCapture.ToHex(data),
            AsciiPreview = PacketCapture.ToAscii(data)
        });
    }
}