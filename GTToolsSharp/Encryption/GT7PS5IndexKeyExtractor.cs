using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace GTToolsSharp.Encryption;

/// <summary>
/// Finds the GT7 PS5 index key block inside the user's decrypted game executable (eboot.bin as an ELF),
/// so no key material has to ship with this tool.
/// </summary>
/// <remarks>
/// The block is a 64-byte ChaCha20 state in a data segment, stored next to the "/app0/contents/gt.idx"
/// path option. Candidates near that string are tried first, then every 4-byte aligned window of the
/// executable's non-executable segments. A candidate is accepted only if it decrypts the first block of
/// the given index to a valid superintendent header (magic and formatter code).
/// </remarks>
public static class GT7PS5IndexKeyExtractor
{
    private const int NearStringRange = 0x1000;
    private static readonly byte[] IndexPathString = Encoding.ASCII.GetBytes("/app0/contents/gt.idx\0");

    public static byte[] FindIndexKey(string executablePath, ReadOnlySpan<byte> encryptedIndex, out string error)
    {
        error = null;
        if (encryptedIndex.Length < 0x40)
        {
            error = "Index file is too small.";
            return null;
        }

        byte[] elf = File.ReadAllBytes(executablePath);
        if (elf.Length < 0x40 || BinaryPrimitives.ReadUInt32BigEndian(elf) != 0x7F454C46 || elf[4] != 2)
        {
            error = "Executable is not a 64-bit ELF. Provide the decrypted executable (eboot.bin decrypted to ELF), not the signed SELF.";
            return null;
        }

        uint expected = GT7PS5IndexCrypto.ExpectedKeystreamWord0(BinaryPrimitives.ReadUInt32LittleEndian(encryptedIndex));
        byte[] firstBlock = encryptedIndex[..0x40].ToArray();

        foreach (var (start, end) in GetSearchRanges(elf))
        {
            for (int offset = start; offset + GT7PS5IndexCrypto.StateSize <= end; offset += 4)
            {
                ReadOnlySpan<byte> candidate = elf.AsSpan(offset, GT7PS5IndexCrypto.StateSize);
                if (GT7PS5IndexCrypto.Block0Word0(candidate) != expected)
                    continue;

                byte[] test = (byte[])firstBlock.Clone();
                GT7PS5IndexCrypto.Decrypt(test, candidate);
                if (GT7PS5IndexCrypto.IsDecryptedHeader(test))
                {
                    Program.Log($"[:] Found the PS5 index key block at executable offset 0x{offset:X}");
                    return candidate.ToArray();
                }
            }
        }

        error = "The index key was not found in this executable. Make sure the executable and the index come from the same GT7 PS5 version.";
        return null;
    }

    private static IEnumerable<(int Start, int End)> GetSearchRanges(byte[] elf)
    {
        // Near each occurrence of the index path option first (the key block follows it closely)
        int at = 0;
        while (at < elf.Length)
        {
            int relative = elf.AsSpan(at).IndexOf(IndexPathString);
            if (relative == -1)
                break;

            int found = at + relative;
            int start = Math.Max(0, found - NearStringRange) & ~3;
            yield return (start, Math.Min(elf.Length, found + NearStringRange));
            at = found + IndexPathString.Length;
        }

        // Then every non-executable loadable segment
        ulong programHeaderOffset = BinaryPrimitives.ReadUInt64LittleEndian(elf.AsSpan(0x20));
        ushort programHeaderSize = BinaryPrimitives.ReadUInt16LittleEndian(elf.AsSpan(0x36));
        ushort programHeaderCount = BinaryPrimitives.ReadUInt16LittleEndian(elf.AsSpan(0x38));
        for (int i = 0; i < programHeaderCount; i++)
        {
            long entry = (long)programHeaderOffset + (long)i * programHeaderSize;
            if (entry + 0x38 > elf.Length)
                yield break;

            ReadOnlySpan<byte> header = elf.AsSpan((int)entry, 0x38);
            uint type = BinaryPrimitives.ReadUInt32LittleEndian(header);
            uint flags = BinaryPrimitives.ReadUInt32LittleEndian(header[4..]);
            ulong fileOffset = BinaryPrimitives.ReadUInt64LittleEndian(header[8..]);
            ulong fileSize = BinaryPrimitives.ReadUInt64LittleEndian(header[0x20..]);

            const uint PT_LOAD = 1, PF_X = 1;
            if (type != PT_LOAD || (flags & PF_X) != 0 || fileOffset >= (ulong)elf.Length)
                continue;

            int start = (int)fileOffset & ~3;
            int end = (int)Math.Min((ulong)elf.Length, fileOffset + fileSize);
            yield return (start, end);
        }
    }
}
