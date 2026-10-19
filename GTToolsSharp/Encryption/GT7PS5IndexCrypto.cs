using System;
using System.Buffers.Binary;

using PDTools.Hashing;

namespace GTToolsSharp.Encryption;

/// <summary>
/// Encryption of the GT7 PS5 volume index (contents/gt.idx).
/// </summary>
/// <remarks>
/// PDISTD::FileSystemMPH::loadSuperintendentBlock copies the device's 64-byte key block into the
/// ChaCha20 core, used as the whole initial state (there are no standard constants), with word 12 as
/// the 64-byte block counter. The first 0x800 bytes then go through an inverted CRC-32 chain seeded
/// 0x1FD5B434, like the PS4 index (which uses a different seed). Mounting requires the superintendent
/// magic at 0x00 and the formatter code at 0x20.
/// <para>
/// The key block is not stored in this tool: <see cref="GT7PS5IndexKeyExtractor"/> reads it from the
/// user's own decrypted game executable.
/// </para>
/// </remarks>
public static class GT7PS5IndexCrypto
{
    public const uint SuperintendentMagic = 0x122BB8F2;
    public const uint FormatterCode = 0x11160000;
    public const int StateSize = 0x40;
    public const int ScrambledHeaderSize = 0x800;

    private const uint HeaderCrcSeed = 0x1FD5B434;

    /// <summary>
    /// Decrypts a whole index in place.
    /// </summary>
    public static void Decrypt(Span<byte> data, ReadOnlySpan<byte> state)
    {
        ApplyKeystream(data, state);
        UnscrambleHeader(data);
    }

    public static bool IsDecryptedHeader(ReadOnlySpan<byte> data)
    {
        return data.Length >= 0x24
            && BinaryPrimitives.ReadUInt32LittleEndian(data) == SuperintendentMagic
            && BinaryPrimitives.ReadUInt32LittleEndian(data[0x20..]) == FormatterCode;
    }

    public static void ApplyKeystream(Span<byte> data, ReadOnlySpan<byte> state)
    {
        if (state.Length != StateSize)
            throw new ArgumentException($"Index key block must be {StateSize} bytes.", nameof(state));

        Span<uint> input = stackalloc uint[16];
        Span<uint> output = stackalloc uint[16];
        Span<byte> keystream = stackalloc byte[64];
        for (int i = 0; i < 16; i++)
            input[i] = BinaryPrimitives.ReadUInt32LittleEndian(state[(i * 4)..]);

        uint counter = 0;
        for (int offset = 0; offset < data.Length; offset += 64, counter++)
        {
            input[12] = counter;
            Block(input, output);
            for (int i = 0; i < 16; i++)
                BinaryPrimitives.WriteUInt32LittleEndian(keystream[(i * 4)..], output[i]);

            Span<byte> chunk = data.Slice(offset, Math.Min(64, data.Length - offset));
            for (int i = 0; i < chunk.Length; i++)
                chunk[i] ^= keystream[i];
        }
    }

    /// <summary>
    /// Undoes the CRC chain over the first 0x800 bytes. Each word is xored with the CRC table step of the
    /// previous (still scrambled) word, then inverted.
    /// </summary>
    public static void UnscrambleHeader(Span<byte> data)
    {
        uint previous = HeaderCrcSeed;
        int length = Math.Min(ScrambledHeaderSize, data.Length) & ~3;
        for (int i = 0; i < length; i += 4)
        {
            uint value = BinaryPrimitives.ReadUInt32LittleEndian(data[i..]);
            BinaryPrimitives.WriteUInt32LittleEndian(data[i..], ~(CrcStep(previous) ^ value));
            previous = value;
        }
    }

    /// <summary>
    /// Keystream word 0 of block 0 that turns <paramref name="encryptedWord0"/> into the superintendent
    /// magic. Used to test key block candidates with a single ChaCha20 block.
    /// </summary>
    internal static uint ExpectedKeystreamWord0(uint encryptedWord0)
    {
        return encryptedWord0 ^ ~SuperintendentMagic ^ CrcStep(HeaderCrcSeed);
    }

    internal static uint Block0Word0(ReadOnlySpan<byte> state)
    {
        Span<uint> input = stackalloc uint[16];
        Span<uint> output = stackalloc uint[16];
        for (int i = 0; i < 16; i++)
            input[i] = BinaryPrimitives.ReadUInt32LittleEndian(state[(i * 4)..]);
        input[12] = 0;

        Block(input, output);
        return output[0];
    }

    private static uint CrcStep(uint value)
    {
        uint[] table = CRC32.checksum_0x04C11DB7;
        uint v = table[value >> 24];
        v = v << 8 ^ table[(byte)(value >> 16) ^ (v >> 24)];
        v = v << 8 ^ table[(byte)(value >> 8) ^ (v >> 24)];
        v = v << 8 ^ table[(byte)value ^ (v >> 24)];
        return v;
    }

    private static void Block(ReadOnlySpan<uint> input, Span<uint> output)
    {
        input.CopyTo(output);
        for (int i = 0; i < 10; i++)
        {
            QuarterRound(output, 0, 4, 8, 12);
            QuarterRound(output, 1, 5, 9, 13);
            QuarterRound(output, 2, 6, 10, 14);
            QuarterRound(output, 3, 7, 11, 15);
            QuarterRound(output, 0, 5, 10, 15);
            QuarterRound(output, 1, 6, 11, 12);
            QuarterRound(output, 2, 7, 8, 13);
            QuarterRound(output, 3, 4, 9, 14);
        }

        for (int i = 0; i < 16; i++)
            output[i] += input[i];
    }

    private static void QuarterRound(Span<uint> x, int a, int b, int c, int d)
    {
        x[a] += x[b]; x[d] = uint.RotateLeft(x[d] ^ x[a], 16);
        x[c] += x[d]; x[b] = uint.RotateLeft(x[b] ^ x[c], 12);
        x[a] += x[b]; x[d] = uint.RotateLeft(x[d] ^ x[a], 8);
        x[c] += x[d]; x[b] = uint.RotateLeft(x[b] ^ x[c], 7);
    }
}
