// Copyright 2021 - Haga Rakotoharivelo - https://github.com/haga-rak

using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Fluxzy.Misc.Streams
{
    public delegate Task DisposeFunc(object sender, StreamDisposeEventArgs args);

    public class DisposeEventNotifierStream : Stream
    {
        private readonly Stream _innerStream;

        private int _totalRead;

        public DisposeEventNotifierStream(Stream innerStream)
        {
            _innerStream = innerStream;
        }

        public override bool CanRead => _innerStream.CanRead;

        public override bool CanSeek => _innerStream.CanSeek;

        public override bool CanWrite => _innerStream.CanWrite;

        public override long Length => _innerStream.Length;

        public override long Position {
            get => _innerStream.Position;
            set => _innerStream.Position = value;
        }

        public event DisposeFunc? OnStreamDisposed;

        public override void Flush()
        {
            _innerStream.Flush();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            try {
                var res = _innerStream.Read(buffer, offset, count);

                _totalRead += res;

                return res;
            }
            catch {
                return 0; // JUST RETURN EOF when fail
            }
        }

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = new())
        {
            return await _innerStream.ReadAsync(buffer, cancellationToken);
        }

        public override async Task<int> ReadAsync(
            byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            return await ReadAsync(new Memory<byte>(buffer, offset, count), cancellationToken);
        }

        public override int Read(Span<byte> buffer)
        {
            return _innerStream.Read(buffer);
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            return _innerStream.Seek(offset, origin);
        }

        public override void SetLength(long value)
        {
            _innerStream.SetLength(value);
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            _innerStream.Write(buffer, offset, count);
        }

        public override async ValueTask WriteAsync(
            ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = new())
        {
            await _innerStream.WriteAsync(buffer, cancellationToken);
        }

        public override async Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            await WriteAsync(new ReadOnlyMemory<byte>(buffer, offset, count), cancellationToken);
        }

        public override async ValueTask DisposeAsync()
        {
            await _innerStream.DisposeAsync();

            if (OnStreamDisposed != null)
                await OnStreamDisposed(this, new StreamDisposeEventArgs());
        }
    }
}
