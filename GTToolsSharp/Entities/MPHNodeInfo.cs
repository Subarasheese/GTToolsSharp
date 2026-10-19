
using System;
using System.Buffers.Binary;

using PDTools.Utils;

namespace GTToolsSharp.Entities;

public class MPHNodeInfo
{
    public int NodeIndex { get; set; }

    public uint EntryHash { get; set; }
    public uint Nonce { get; set; }
    public ulong CompressedSize { get; set; }
    public ulong UncompressedSize;
    public MPHNodeFormat Format { get; set; }
    public bool ForcedEncryptionIfPlain { get; set; }
    public MPHNodeKind Kind { get; set; }
    public MPHNodeAlgo Algo { get; set; }

    public byte ExtraFlags { get; set; }

    public uint SectorPlusVolumeIndexBits { get; set; }

    /// <summary>
    /// PS5: seed of the node's file name in the contents folder (see <see cref="GTToolsSharp.Volumes.GTVolumeMPH.GetCacheKey(uint)"/>).
    /// Nodes with identical contents share the same file.
    /// </summary>
    public uint FileSeed { get; set; }

    /// <summary>
    /// PS5: whether the file is stored compressed (PS2ZIP), and must be inflated to <see cref="UncompressedSize"/>.
    /// </summary>
    public bool IsCompressed { get; set; }

    public void Read(ref BitStream bs)
    {
        EntryHash = bs.ReadUInt32();
        uint compressedSizeLow = bs.ReadUInt32();
        Nonce = bs.ReadUInt32();
        uint uncompressedSizeLow = bs.ReadUInt32();

        SectorPlusVolumeIndexBits = bs.ReadUInt32();

        CompressedSize = ((ulong)bs.ReadByte() << 32) | compressedSizeLow;

        Format = (MPHNodeFormat)bs.ReadBits(2);
        ForcedEncryptionIfPlain = bs.ReadBoolBit();
        bs.ReadBoolBit(); // No idea

        Kind = (MPHNodeKind)bs.ReadBits(2);
        Algo = (MPHNodeAlgo)bs.ReadBits(2);

        UncompressedSize = ((ulong)bs.ReadByte() << 32) | uncompressedSizeLow;

        ExtraFlags = (byte)bs.ReadByte();
    }

    /// <summary>
    /// Reads a GT7 PS5 node (24 bytes, little endian).
    /// </summary>
    /// <remarks>
    /// 0x00 path hash (fnv1a), 0x04 stored size, 0x08 contents hash (shared by identical files),
    /// 0x0C uncompressed size, 0x10 file seed, 0x14 stored size bits 32-39, 0x15 uncompressed size bits 32-39,
    /// 0x16 flags (bit 0: compressed), 0x17 extra flags (0: file in the contents folder).
    /// </remarks>
    public void ReadPS5(ReadOnlySpan<byte> data)
    {
        EntryHash = BinaryPrimitives.ReadUInt32LittleEndian(data);
        uint compressedSizeLow = BinaryPrimitives.ReadUInt32LittleEndian(data[0x04..]);
        Nonce = BinaryPrimitives.ReadUInt32LittleEndian(data[0x08..]);
        uint uncompressedSizeLow = BinaryPrimitives.ReadUInt32LittleEndian(data[0x0C..]);
        FileSeed = BinaryPrimitives.ReadUInt32LittleEndian(data[0x10..]);
        CompressedSize = ((ulong)data[0x14] << 32) | compressedSizeLow;
        UncompressedSize = ((ulong)data[0x15] << 32) | uncompressedSizeLow;
        IsCompressed = (data[0x16] & 1) != 0;
        ExtraFlags = data[0x17];
    }

    public uint GetSectorIndex()
    {
        return SectorPlusVolumeIndexBits & 0b1_11111111_11111111_11111111; // 25 bits
    }

    public byte GetVolumeIndex()
    {
        return (byte)(SectorPlusVolumeIndexBits >> 25); // 7 bits
    }

    public byte GetDictIndex()
    {
        return (byte)(ExtraFlags & 0x1111); // 4 bits
    }

    public bool IsFromClusterVolume()
    {
        return (ExtraFlags & 0x80) != 0;
    }

    public bool IsFromPFSStyleFile()
    {
        return (ExtraFlags & 0x80) == 0;
    }
}

public enum MPHNodeFormat
{
    PLAIN,
    PFS,
    PZ1,
    PZ2
}

public enum MPHNodeKind
{
    LUMP,
    FRAG,
}

public enum MPHNodeAlgo
{
    ZLIB,
    ZSTD,
    KRAKEN,
}
