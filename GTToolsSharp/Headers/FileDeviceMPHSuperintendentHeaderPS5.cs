using System;
using System.IO;

using Syroot.BinaryData.Core;
using Syroot.BinaryData.Memory;

using GTToolsSharp.Encryption;
using GTToolsSharp.Entities;

namespace GTToolsSharp.Headers;

/// <summary>
/// GT7 PS5 superintendent header (decrypted contents/gt.idx).
/// </summary>
/// <remarks>
/// Same fields as the PS4 header, but little endian and byte aligned. The indexer does not store its
/// rank tables, and nodes point to files in the contents folder (contents/X/Y/NAME, from the node's
/// file seed) instead of cluster volumes.
/// </remarks>
internal class FileDeviceMPHSuperintendentHeaderPS5 : FileDeviceMPHSuperintendentHeader
{
    public const int NodeSize = 0x18;

    public uint RandomValue1 { get; set; }
    public uint RandomValue2 { get; set; }
    public byte[] Digest { get; set; }

    public override void Read(Span<byte> buffer)
    {
        SpanReader sr = new SpanReader(buffer, Endian.Little);

        Magic = sr.ReadBytes(4);
        RandomValue1 = sr.ReadUInt32();
        JulianTimestamp = sr.ReadUInt64();
        SerialNumber = sr.ReadUInt64();
        RandomValue2 = sr.ReadUInt32();
        Flags = sr.ReadUInt32();
        FormatterCode = sr.ReadUInt32();

        if (FormatterCode != GT7PS5IndexCrypto.FormatterCode)
            Program.Log($"Warning: Superintendent formatter code does not match 0x{GT7PS5IndexCrypto.FormatterCode:X8}");

        IndexDataOffset = sr.ReadUInt32();
        IndexDataSize = sr.ReadUInt32();
        NodeInfoOffset = sr.ReadUInt32();
        NodeInfoSize = sr.ReadUInt32();
        VolumeInfoOffset = sr.ReadUInt32();
        VolumeInfoCount = sr.ReadUInt32();
        DictInfoOffset = sr.ReadUInt32();
        DictInfoCount = sr.ReadUInt32();
        Digest = sr.ReadBytes(0x10);

        if (VolumeInfoCount != 0)
            throw new InvalidDataException($"PS5 index references {VolumeInfoCount} cluster volumes, which are not supported.");

        VolumeInfo = [];

        sr.Position = (int)IndexDataOffset;
        Indexer.ReadPS5(ref sr);

        if ((long)NodeInfoOffset + (long)Indexer.NodeCount * NodeSize > buffer.Length)
            throw new InvalidDataException("PS5 index node table is out of bounds.");

        Nodes = new MPHNodeInfo[Indexer.NodeCount];
        for (var i = 0; i < Indexer.NodeCount; i++)
        {
            MPHNodeInfo node = new MPHNodeInfo();
            node.NodeIndex = i;
            node.ReadPS5(buffer.Slice((int)NodeInfoOffset + i * NodeSize, NodeSize));
            Nodes[i] = node;
        }
    }

    public override void PrintInfo()
    {
        Program.Log("[>] Platform: PS5");
        Program.Log($"[>] PFS Version/Serial No: '{SerialNumber}' ({new DateTime(2001, 1, 1) + TimeSpan.FromSeconds(SerialNumber)})");
        Program.Log($"[>] Formatter Code: 0x{FormatterCode:X8}");
        Program.Log($"[>] Flags: 0x{Flags:X8}");
        Program.Log($"[>] Index Data Offset: 0x{IndexDataOffset:X8}");
        Program.Log($"[>] Index Data Size: 0x{IndexDataSize:X8}");
        Program.Log($"[>] Node Info Offset: 0x{NodeInfoOffset:X8}");
        Program.Log($"[>] Node Info Size: 0x{NodeInfoSize:X8}");
        Program.Log($"[>] Node Count: {Indexer.NodeCount}");
    }
}
