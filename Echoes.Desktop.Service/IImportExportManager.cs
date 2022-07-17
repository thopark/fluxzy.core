﻿namespace Echoes.Desktop.Service
{
    public interface IGlobalFileManager
    {
        Task<IFileState> New();

        Task<IFileState> Close();

        Task<IFileState> Open(string fileName); 

        Task<IFileState> Save(string fileName, Guid fileSessionIdentifier); 

        Task<IFileState> Export(Stream outStream, IFileState fileState, EchoesFileType fileType); 
    }

    public interface IFileSessionManager
    {
        Task<UiState> New(); 

        Task<IReadOnlyCollection<IEchoesSession>> ReadEntries(Guid fileIdentifier,
            int start, int count); 

        Task AppendEntries(Guid fileIdentifier,
            IEnumerable<IEchoesSession> sessions); 

        Task RemoveEntries(Guid fileIdentifier,
            IEnumerable<int> sessionId); 
    }

    public enum EchoesFileType
    {
        Error = 0,
        Native = 1 , 
        Har = 5 , 
        Saz = 50 , 
    }

    public interface IFileState
    {
        Guid Identifier { get;  }
        
        string ?  FullPath { get;  }

        EchoesFileType Type { get;  }

        long ? EntryCount { get; }

        DateTime ? LastModificationUtc { get;  }
    }


    public interface IEchoesSession
    {
        long Id { get;  }

        string Method { get;  }
    }
}