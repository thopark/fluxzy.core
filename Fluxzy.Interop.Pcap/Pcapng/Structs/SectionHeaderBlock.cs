// // Copyright 2022 - Haga Rakotoharivelo
// 

using System.Buffers.Binary;
using System.Text;

namespace Fluxzy.Interop.Pcap.Pcapng.Structs
{
    public readonly ref struct SectionHeaderBlock
    {
        public SectionHeaderBlock(int optionLength)
        {
            BlockTotalLength = 24 + optionLength + 4;
        }

        public uint BlockType { get; init; } = 0x0A0D0D0A;

        public int BlockTotalLength { get; } 

        public uint ByteOrderMagic { get; init; } = 0x1A2B3C4D;
        
        public ushort MajorVersion { get; init; } = 1;

        public ushort MinorVersion { get; init; } = 0;

        public ulong SectionLength { get; init; } = 0xFFFFFFFFFFFFFFFF;

        public int OnWireLength => BlockTotalLength;

        public int WriteHeader(Span<byte> buffer)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(buffer, BlockType);
            BinaryPrimitives.WriteInt32LittleEndian(buffer.Slice(4), BlockTotalLength);
            BinaryPrimitives.WriteUInt32LittleEndian(buffer.Slice(8), ByteOrderMagic);
            BinaryPrimitives.WriteUInt16LittleEndian(buffer.Slice(12), MajorVersion);
            BinaryPrimitives.WriteUInt16LittleEndian(buffer.Slice(14), MinorVersion);
            BinaryPrimitives.WriteUInt64LittleEndian(buffer.Slice(16), SectionLength);

            return 24;
        }
        
        public int WriteTrailer(Span<byte> buffer)
        {
            BinaryPrimitives.WriteInt32LittleEndian(buffer, BlockTotalLength);
            return 4;
        }
    }


    public readonly ref struct NssDecryptionSecretsBlock
    {
        public NssDecryptionSecretsBlock(string nssKey)
        {
            BlockTotalLength = 20;
            SecretsLength = Encoding.UTF8.GetByteCount(nssKey) ; 
            BlockTotalLength += SecretsLength + (((4 - SecretsLength % 4) % 4));
        }

        public uint BlockType { get; init; } = 0x0000000A;

        public int BlockTotalLength { get; }

        public int SecretsType { get; } = 0x544c534b;

        public int SecretsLength { get; }

        public int Write(Span<byte> buffer, string nssKey)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(buffer, BlockType);
            BinaryPrimitives.WriteInt32LittleEndian(buffer.Slice(4), BlockTotalLength);
            BinaryPrimitives.WriteInt32LittleEndian(buffer.Slice(8), SecretsType);
            BinaryPrimitives.WriteInt32LittleEndian(buffer.Slice(12), SecretsLength);
            
            Encoding.UTF8.GetBytes(nssKey, buffer.Slice(16));

            var offset = 16 + SecretsLength + (((4 - SecretsLength % 4) % 4));

            BinaryPrimitives.WriteInt32LittleEndian(buffer.Slice(offset), BlockTotalLength);

            return BlockTotalLength;

        }
    }
}