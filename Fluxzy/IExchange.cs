// Copyright © 2022 Haga Rakotoharivelo

using System.Collections.Generic;
using Fluxzy.Clients.H11;

namespace Fluxzy
{
    public interface IExchange
    {
        string FullUrl { get; }

        string KnownAuthority { get; }

        string HttpVersion { get; }

        string Method { get; }

        string Path { get; }

        int StatusCode { get; }

        string? EgressIp { get; }

        string? Comment { get; }

        HashSet<Tag>? Tags { get; }

        bool IsWebSocket { get; }

        List<WsMessage>? WebSocketMessages { get; }

        IEnumerable<HeaderFieldInfo> GetRequestHeaders();

        IEnumerable<HeaderFieldInfo>? GetResponseHeaders();
        
        Agent ? Agent { get;  }

        List<ClientError> ClientErrors { get;  }
    }


    public class ClientError
    {
        public ClientError(int errorCode, string message)
        {
            ErrorCode = errorCode;
            Message = message;
        }

        public int ErrorCode { get;  }
        

        public string Message { get; }


        public string ? ExceptionMessage { get; set; }
    }
    
}
