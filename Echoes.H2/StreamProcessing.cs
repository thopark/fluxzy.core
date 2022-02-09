﻿using System;
using System.Buffers;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Echoes.Encoding.Utils;

namespace Echoes.H2
{
    internal class StreamProcessing: IDisposable
    {
        private readonly StreamPool _parent;
        private readonly Exchange _exchange;
        private readonly CancellationToken _callerCancellationToken;
        private readonly UpStreamChannel _upStreamChannel;
        private readonly IHeaderEncoder _headerEncoder;
        private readonly H2Message _response;
        
        private readonly Memory<byte> _dataReceptionBuffer;
        private readonly H2StreamSetting _globalSetting;
        private readonly Http11Parser _parser;

        private readonly TaskCompletionSource<object> _responseHeaderReady = new TaskCompletionSource<object>();
        private readonly TaskCompletionSource<object> _responseBodyComplete = new TaskCompletionSource<object>();

        private readonly CancellationTokenSource _currentStreamCancellationTokenSource;
        private readonly MutableMemoryOwner<byte> _receptionBufferContainer;

        private H2ErrorCode _resetErrorCode;

        public StreamProcessing(
            int streamIdentifier,
            StreamPool parent,
            Exchange exchange, 
            UpStreamChannel upStreamChannel,
            IHeaderEncoder headerEncoder,
            H2StreamSetting globalSetting,
            WindowSizeHolder overallWindowSizeHolder,
            Http11Parser parser, 
            CancellationToken mainLoopCancellationToken,
            CancellationToken callerCancellationToken)
        {
            StreamIdentifier = streamIdentifier;
            _parent = parent;
            _exchange = exchange;
            _callerCancellationToken = callerCancellationToken;
            _upStreamChannel = upStreamChannel;
            _headerEncoder = headerEncoder;
            _response = new H2Message(headerEncoder.Decoder, StreamIdentifier, MemoryPool<byte>.Shared, this);
            RemoteWindowSize = new WindowSizeHolder(globalSetting.OverallWindowSize, streamIdentifier);
            OverallRemoteWindowSize = overallWindowSizeHolder; 
            
            _globalSetting = globalSetting;
            _parser = parser;

            _receptionBufferContainer = MemoryPool<byte>.Shared.RendExact(16 * 1024);

            _dataReceptionBuffer = _receptionBufferContainer.Memory;
            
            _currentStreamCancellationTokenSource =
                CancellationTokenSource.CreateLinkedTokenSource(callerCancellationToken, mainLoopCancellationToken);

            _currentStreamCancellationTokenSource.Token.Register(OnStreamHaltRequest);
        }

        private void OnStreamHaltRequest()
        {
            if (_resetErrorCode != H2ErrorCode.NoError)
            {
                // The stream was reset by remote peer.
                // Send an exception to the caller 

                var rstStreamException = new H2Exception(
                    $"Stream id {StreamIdentifier} halt with a RST_STREAM : {_resetErrorCode}",
                    _resetErrorCode);

                _responseHeaderReady.TryEnd(rstStreamException);
                _responseBodyComplete.TryEnd(rstStreamException);

                return; 
            }

            if (_callerCancellationToken.IsCancellationRequested)
            {
                // The caller cancelled the request 
                _responseHeaderReady.TryEnd();
                _responseBodyComplete.TryEnd();
                return;
            }

            // In case of exception in the main loop, we ensure that wait tasks for the caller are 
            // properly interrupt with exception

            var goAwayException = _parent.GoAwayException;

            _responseHeaderReady.TryEnd(goAwayException);
            _responseBodyComplete.TryEnd(goAwayException);
        }
        
        public int StreamIdentifier { get;  }

        public byte StreamPriority { get; private set; }

        public int StreamDependency { get; private set; }

        public bool Exclusive { get; private set; }

        public WindowSizeHolder RemoteWindowSize { get;  }
        
        public WindowSizeHolder OverallRemoteWindowSize { get;  }
        
        private async ValueTask<bool> BookWindowSize(int minimumBodyLength, CancellationToken cancellationToken)
        {
            if (minimumBodyLength == 0)
                return true; 

            if (!await RemoteWindowSize.BookWindowSize(minimumBodyLength, cancellationToken).ConfigureAwait(false))
                return false;

            if (!await OverallRemoteWindowSize.BookWindowSize(minimumBodyLength, cancellationToken).ConfigureAwait(false))
                return false;

            return true;
        }

        public void NotifyRemoteWindowUpdate(int windowSizeUpdateValue)
        {
            RemoteWindowSize.UpdateWindowSize(windowSizeUpdateValue);
        }

        public void ResetRequest(H2ErrorCode errorCode)
        {
            _resetErrorCode = errorCode;
            _currentStreamCancellationTokenSource.Cancel(true);
        }

        public void SetPriority(PriorityFrame priorityFrame)
        {
            StreamDependency = priorityFrame.StreamDependency;
            StreamPriority = priorityFrame.Weight;
            Exclusive = priorityFrame.Exclusive; 
        }
        
        public Task EnqueueRequestHeader(Exchange exchange)
        {
            var readyToBeSent = _headerEncoder.Encode(
                new HeaderEncodingJob(exchange.Request.Header.RawHeader, StreamIdentifier, StreamDependency), 
                _dataReceptionBuffer, exchange.Request.Header.ContentLength == 0 || 
                                      exchange.Request.Body == null);

            exchange.Metrics.RequestHeaderSending = ITimingProvider.Default.Instant();

            var writeHeaderTask = new WriteTask(H2FrameType.Headers, StreamIdentifier, StreamPriority,
                StreamDependency, readyToBeSent);

            _upStreamChannel(ref writeHeaderTask);
            

            return writeHeaderTask.DoneTask
                .ContinueWith(t => _exchange.Metrics.TotalSent += readyToBeSent.Length, _callerCancellationToken);

          //  return writeHeaderTask.DoneTask;
        }
        
        public async Task ProcessRequestBody(Exchange exchange)
        {
            var totalSent = 0;
            Stream requestBodyStream = exchange.Request.Body;
            long bodyLength = exchange.Request.Header.ContentLength;



            if (requestBodyStream != null)
            {
                while (true)
                {
                    var requestedSize = _globalSetting.Remote.MaxFrameSize - 9;

                    var readLength = await requestBodyStream
                        .ReadAsync(_dataReceptionBuffer.Slice(9, requestedSize), _currentStreamCancellationTokenSource.Token)
                        .ConfigureAwait(false);

                    if (!await BookWindowSize(readLength, _currentStreamCancellationTokenSource.Token)
                            .ConfigureAwait(false))
                        throw new OperationCanceledException("Stream cancellation request",
                            _currentStreamCancellationTokenSource.Token);

                    var endStream = readLength == 0;

                    if (bodyLength >= 0 && (totalSent + readLength) >= bodyLength)
                    {
                        endStream = true;
                    }

                    new DataFrame(endStream ? HeaderFlags.EndStream : HeaderFlags.None, readLength,
                        StreamIdentifier).WriteHeaderOnly(_dataReceptionBuffer.Span, readLength);

                    var writeTaskBody = new WriteTask(H2FrameType.Data, StreamIdentifier,
                        StreamPriority, StreamDependency,
                        _dataReceptionBuffer.Slice(0, 9 + readLength));

                    _upStreamChannel(ref writeTaskBody);


                    totalSent += readLength;
                    _exchange.Metrics.TotalSent += readLength;

                    if (readLength > 0)
                        NotifyRemoteWindowUpdate(-readLength);



                    if (readLength == 0 || endStream)
                    {
                        // No more request data body to send 
                        return;
                    }

                    await writeTaskBody.DoneTask.ConfigureAwait(false);

                }
            }
        }

        public async Task<H2Message> ProcessResponse(CancellationToken cancellationToken)
        {
            await _responseHeaderReady.Task.ConfigureAwait(false);
            return _response;
        }

        internal void ReceiveHeaderFragmentFromConnection(HeadersFrame headersFrame)
        {
            _exchange.Metrics.TotalReceived += headersFrame.BodyLength;
            _exchange.Metrics.ResponseHeaderStart = ITimingProvider.Default.Instant(); 
            ReceiveHeaderFragmentFromConnection(headersFrame.Data, headersFrame.EndHeaders);
        }

        internal void ReceiveHeaderFragmentFromConnection(ContinuationFrame continuationFrame)
        {
            _exchange.Metrics.TotalReceived += continuationFrame.BodyLength;
            ReceiveHeaderFragmentFromConnection(continuationFrame.Data, continuationFrame.EndHeaders);
        }

        private void ReceiveHeaderFragmentFromConnection(ReadOnlyMemory<byte> buffer, bool last)
        {
            if (last)
            {
                _exchange.Metrics.ResponseHeaderEnd = ITimingProvider.Default.Instant();
            }

            _response.PostResponseHeader(buffer, last);

            _exchange.Response.Header = new ResponseHeader(
                _response.Header.AsMemory(), true, _parser);

            if (last)
                _responseHeaderReady.SetResult(null);
        }

        private bool _firstBodyFragment = true; 

        public void ReceiveBodyFragmentFromConnection(ReadOnlyMemory<byte> buffer, bool endStream)
        {
            if (_firstBodyFragment)
            {
                _exchange.Metrics.ResponseBodyStart = ITimingProvider.Default.Instant();
                _firstBodyFragment = false; 
            }

            if (endStream)
            {
                _exchange.Metrics.ResponseBodyEnd = ITimingProvider.Default.Instant();
            }


            _exchange.Metrics.TotalReceived += buffer.Length;

            _response.PostResponseBodyFragment(buffer, endStream);

            if (endStream)
            {
                _responseBodyComplete.SetResult(null);
                _parent.NotifyDispose(this);
                _exchange.ExchangeCompletionSource.SetResult(false);
            }
        }
        
        internal void OnDataConsumedByCaller(int dataSize)
        {
            if (dataSize > 0)
            {
                SendWindowUpdate(dataSize, StreamIdentifier);
                SendWindowUpdate(dataSize, 0);
            }
        }

        private void SendWindowUpdate(int windowSizeUpdateValue, int streamIdentifier)
        {
            var writeTask = new WriteTask(
                H2FrameType.WindowUpdate,
                streamIdentifier, StreamPriority, 
                StreamDependency, Memory<byte>.Empty, windowSizeUpdateValue);
            _upStreamChannel(ref writeTask);
        }

        private void OnError(Exception ex)
        {
            _parent.NotifyDispose(this);
        }

        public override string ToString()
        {
            return $"Stream Id : {StreamIdentifier} : {_responseHeaderReady.Task.Status} : {_responseBodyComplete.Task.Status}"; 
        }

        public void Dispose()
        {
            RemoteWindowSize?.Dispose();
            OverallRemoteWindowSize?.Dispose();
            _currentStreamCancellationTokenSource.Dispose();
            _receptionBufferContainer?.Dispose();
        }
    }
    
}