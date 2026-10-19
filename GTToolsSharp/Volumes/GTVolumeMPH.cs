using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.IO;
using System.Threading.Tasks;
using System.Threading;

using GTToolsSharp.Entities;
using GTToolsSharp.Headers;

using PDTools.Crypto;
using PDTools.Hashing;
using GTToolsSharp.Encryption;

using PDTools.Compression;

namespace GTToolsSharp.Volumes;

/// <summary>
/// GT7 Volume based on Minimal Perfect Hash. (Disposable object)
/// </summary>
public class GTVolumeMPH : IDisposable
{
    private static List<string> _dmsEntryList { get; set; } = [];

    public string InputPath { get; set; }
    public string OutputDirectory { get; set; }

    public bool NoCompress { get; set; }

    public byte[] VolumeHeaderData { get; private set; }

    public ClusterVolume[] SplitVolumes { get; set; }
    public FileStream MainStream { get; }

    public MPHVolumeHeaderBase VolumeHeader { get; set; }

    static GTVolumeMPH()
    {
        if (File.Exists("FileLists/dmsdata.txt"))
        {
            var lines = File.ReadAllLines("FileLists/dmsdata.txt");
            foreach (var line in lines)
            {
                if (string.IsNullOrEmpty(line) || line.Trim().StartsWith("//"))
                    continue;

                _dmsEntryList.Add(line);
            }
        }

    }

    private GTVolumeMPH(FileStream sourceStream)
    {
        MainStream = sourceStream;
    }

    /// <summary>
    /// Folder holding the index. On PS5, node files are stored under it (contents/X/Y/NAME).
    /// </summary>
    public string ContentsDirectory { get; private set; }

    public bool IsPS5 => VolumeHeader is FileDeviceMPHSuperintendentHeaderPS5;

    /// <summary>
    /// Loads a volume file.
    /// </summary>
    /// <param name="path">Index file (gt.idx).</param>
    /// <param name="ps5ExecutablePath">PS5 only: decrypted game executable to read the index key from.
    /// If not provided, eboot.bin/eboot.elf next to the contents folder is tried.</param>
    /// <returns></returns>
    public static GTVolumeMPH Load(string path, string ps5ExecutablePath = null)
    {
        FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read);
        GTVolumeMPH vol = new GTVolumeMPH(fs);
        vol.InputPath = path;
        vol.ContentsDirectory = Path.GetDirectoryName(Path.GetFullPath(path));

        byte[] headerMagic = new byte[4];
        fs.ReadExactly(headerMagic);

        Span<byte> tmp = new byte[4];
        headerMagic.AsSpan().CopyTo(tmp);

        var headerType = MPHVolumeHeaderBase.Detect(tmp);
        if (headerType == MPHVolumeHeaderType.Unknown)
        {
            var tmpData = new byte[fs.Length];
            fs.Position = 0;
            fs.ReadExactly(tmpData);

            if (GT7PS5IndexCrypto.IsDecryptedHeader(tmpData))
            {
                Program.Log("[:] Index is a decrypted PS5 index.");
                return vol.LoadPS5(tmpData) ? vol : null;
            }

            byte[] encrypted = (byte[])tmpData.Clone();
            DecryptHeader(tmpData);

            headerType = MPHVolumeHeaderBase.Detect(tmpData);
            if (headerType == MPHVolumeHeaderType.Unknown)
                return vol.TryLoadEncryptedPS5(encrypted, ps5ExecutablePath) ? vol : null;
        }

        if (headerType == MPHVolumeHeaderType.Unknown)
        {
            Program.Log("[X] Failed to decrypt volume or volume is not a GT7 MPH volume.");
            fs?.Dispose();
            return null;
        }

        fs.Position = 0;
        vol.VolumeHeader = MPHVolumeHeaderBase.Load(fs, vol, headerType, out byte[] headerBytes);
        vol.VolumeHeaderData = headerBytes;

        if (Program.SaveHeader)
        {
            File.WriteAllBytes("VolumeHeader.bin", vol.VolumeHeaderData);
            Program.Log("Saved decrypted header as VolumeHeader.bin", forceConsolePrint: true);
        }

        vol.VolumeHeader.PrintInfo();
        vol.LoadSplitVolumesIfNeeded();

        return vol;
    }

    private bool TryLoadEncryptedPS5(byte[] encrypted, string executablePath)
    {
        executablePath ??= FindPS5Executable(ContentsDirectory);
        if (executablePath is null)
        {
            Program.Log("[X] Failed to decrypt volume or volume is not a GT7 MPH volume. " +
                "If this is a GT7 PS5 index, provide the decrypted game executable (--elf) to read the index key from.", forceConsolePrint: true);
            Dispose();
            return false;
        }

        Program.Log($"[-] Reading the PS5 index key from '{executablePath}'..", forceConsolePrint: true);
        byte[] key = GT7PS5IndexKeyExtractor.FindIndexKey(executablePath, encrypted, out string error);
        if (key is null)
        {
            Program.Log($"[X] {error}", forceConsolePrint: true);
            Dispose();
            return false;
        }

        GT7PS5IndexCrypto.Decrypt(encrypted, key);
        return LoadPS5(encrypted);
    }

    private bool LoadPS5(byte[] decrypted)
    {
        var header = new FileDeviceMPHSuperintendentHeaderPS5();
        header.Read(decrypted);

        VolumeHeader = header;
        VolumeHeaderData = decrypted;
        SplitVolumes = [];

        if (Program.SaveHeader)
        {
            File.WriteAllBytes("VolumeHeader.bin", VolumeHeaderData);
            Program.Log("Saved decrypted header as VolumeHeader.bin", forceConsolePrint: true);
        }

        VolumeHeader.PrintInfo();
        return true;
    }

    /// <summary>
    /// Looks for a decrypted executable next to the contents folder (app0/eboot.bin, app0/contents/gt.idx).
    /// </summary>
    private static string FindPS5Executable(string contentsDirectory)
    {
        string appDirectory = Path.GetDirectoryName(contentsDirectory);
        if (appDirectory is null)
            return null;

        foreach (var name in new[] { "eboot.elf", "eboot.bin" })
        {
            string candidate = Path.Combine(appDirectory, name);
            if (!File.Exists(candidate))
                continue;

            using var stream = File.OpenRead(candidate);
            Span<byte> magic = stackalloc byte[4];
            if (stream.Read(magic) == 4 && magic.SequenceEqual("\u007FELF"u8))
                return candidate;

            Program.Log($"[!] '{candidate}' is not a decrypted executable (ELF), skipping it.");
        }

        return null;
    }

    // vol01: piece, 
    // vol04: common/
    // vol07: carparts
    // vol08: livery/style or decal
    // vol10: unknown
    // vol11: sky stuff?
    // vol31: Museum

    public async Task UnpackAllFiles(string outputDirectory)
    {
        Program.Log("[-] Unpacking all files from volume.");

        var h = VolumeHeader as FileDeviceMPHSuperintendentHeader;

        SortedDictionary<string, MPHNodeInfo> gameFiles = RegisterFiles();
        OutputDirectory = outputDirectory;

        Program.Log($"[!] Mapped {gameFiles.Count}/{h.Nodes.Length} files from hashed volume.");

        Dictionary<MPHNodeInfo, string> pathByNode = [];
        foreach (var (path, node) in gameFiles)
            pathByNode.TryAdd(node, path);

        // await ParallelExtractFiles(outputDirectory, h, gameFiles);
        for (int i = 0; i < h.Nodes.Length; i++)
        {
            MPHNodeInfo file = h.Nodes[i];

            if (IsPS5)
            {
                if (pathByNode.TryGetValue(file, out string ps5Path))
                    UnpackPS5File(file, Path.Combine(outputDirectory, ps5Path), ps5Path, -1);
                else
                    UnpackPS5File(file, Path.Combine(outputDirectory, ".undiscovered", $"tmp{i}"), string.Empty, i); // Will be renamed by extension detect

                continue;
            }

            ClusterVolume clusterVolume = file.IsFromClusterVolume() ? SplitVolumes[file.GetVolumeIndex()] : null;

            string outPath;
            string volPath;
            if (pathByNode.TryGetValue(file, out volPath))
            {
                outPath = Path.Combine(outputDirectory, volPath);
            }
            else
            {
                volPath = string.Empty;
                if (file.IsFromClusterVolume())
                    outPath = Path.Combine(outputDirectory, ".undiscovered", $"vol{file.GetVolumeIndex()}", $"tmp{i}"); // Will be renamed by extension detect
                else
                    outPath = Path.Combine(".undiscovered", file.NodeIndex.ToString());
            }


            if (file.IsFromClusterVolume())
            {
                if (clusterVolume is not null)
                {
                    clusterVolume.UnpackFile(file, outPath, volPath, -1);
                }
                else
                {
                    Program.Log($"Volume index {file.GetVolumeIndex()} is not loaded, skipping node");
                    continue;
                }
            }
            else if (file.IsFromPFSStyleFile())
            {
                throw new NotImplementedException("PFS Style file not implemented (PS4)");
            }
        }
    }

    public bool UnpackFile(string path, string outputDirectory = "")
    {
        path = path.Replace('\\', '/').TrimStart('/').ToLower();

        var node = (VolumeHeader as FileDeviceMPHSuperintendentHeader).GetNodeByPath(path);
        if (node is null)
            return false;

        if (IsPS5)
        {
            return UnpackPS5File(node, Path.Combine(outputDirectory, path), path, -1);
        }
        else if (node.IsFromClusterVolume())
        {
            ClusterVolume vol = SplitVolumes[node.GetVolumeIndex()];
            vol.UnpackFile(node, Path.Combine(outputDirectory, path), path, -1);
        }
        else if (node.IsFromPFSStyleFile())
        {
            throw new NotImplementedException("PFS Style file not implemented (PS4)");
        }

        return true;
    }

    /// <summary>
    /// Gets the path of a PS5 node's file in the contents folder.
    /// </summary>
    public string GetPS5FilePath(MPHNodeInfo node)
    {
        return Path.Combine(ContentsDirectory, GetCacheKey(node.FileSeed));
    }

    /// <summary>
    /// Extracts a PS5 node. Files are stored unencrypted in the contents folder, some compressed (PS2ZIP).
    /// </summary>
    /// <param name="nodeIndex">If not -1, the output is renamed from its detected file type (undiscovered files).</param>
    private bool UnpackPS5File(MPHNodeInfo node, string outputPath, string volPath, int nodeIndex)
    {
        string sourcePath = GetPS5FilePath(node);
        string cacheKey = GetCacheKey(node.FileSeed);

        if (!File.Exists(sourcePath))
        {
            Program.Log($"[!] Missing contents file '{cacheKey}' for {(string.IsNullOrEmpty(volPath) ? $"node {node.NodeIndex} ({node.EntryHash:X8})" : volPath)}, skipping");
            return false;
        }

        if (!string.IsNullOrEmpty(volPath))
            Program.Log($"[-] Unpacking: {volPath} ({cacheKey}{(node.IsCompressed ? ", compressed" : "")})");
        else
            Program.Log($"[-] Unpacking undiscovered file: {node.EntryHash:X8} ({cacheKey}{(node.IsCompressed ? ", compressed" : "")})");

        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(outputPath)));

        bool success;
        using (FileStream input = File.OpenRead(sourcePath))
        using (FileStream output = new FileStream(outputPath, FileMode.Create))
        {
            if ((ulong)input.Length != node.CompressedSize)
                Program.Log($"[!] Contents file '{cacheKey}' is 0x{input.Length:X} bytes, index says 0x{node.CompressedSize:X}");

            if (node.IsCompressed)
            {
                success = PS2ZIP.TryInflate(input, output);
                if (!success)
                    Program.Log($"[X] Failed to decompress '{cacheKey}'");
            }
            else
            {
                input.CopyTo(output);
                success = true;
            }
        }

        if (success && nodeIndex != -1)
        {
            string ext = DetectExtension(outputPath);
            File.Move(outputPath, Path.Combine(Path.GetDirectoryName(outputPath), $"{nodeIndex}_{node.EntryHash:X8}.{ext}"), overwrite: true);
        }

        return success;
    }

    private static string DetectExtension(string path)
    {
        using FileStream stream = File.OpenRead(path);
        if (stream.Length < 4)
            return "bin";

        uint magic = ClusterVolume.GetMagic(stream, out string asciiMagic);
        return magic switch
        {
            0xe0ffd8ff => "jpg",
            0xE1FFD8FF => "jpg",
            0x200A0D7B => "json",
            0x6d783f3c => "xml",
            0x474e5089 => "png",
            PS2ZIP.PS2ZIP_MAGIC => "pz",
            _ => asciiMagic switch
            {
                null or "" => "bin",
                "ADCH" => "adc",
                _ => asciiMagic,
            },
        };
    }

    public MPHNodeInfo CheckFile(SortedDictionary<string, MPHNodeInfo> validFiles, string path)
    {
        if (path.StartsWith('/'))
            path = path[1..];

        var node = (VolumeHeader as FileDeviceMPHSuperintendentHeader).GetNodeByPath(path.ToLower());
        if (node != null)
        {
            Program.Log($"[/] Valid Volume File: {path} (0x{node.EntryHash:X8})");
            validFiles.TryAdd(path, node);
        }

        if (path.Contains("4k", StringComparison.OrdinalIgnoreCase))
        {
            string _2kPath = path.Replace("4k", "2k");
            node = (VolumeHeader as FileDeviceMPHSuperintendentHeader).GetNodeByPath(_2kPath.ToLower());
            if (node != null)
            {
                Program.Log($"[/] Valid Volume File: {_2kPath} (0x{node.EntryHash:X8})");
                validFiles.TryAdd(_2kPath, node);
            }
        }

        return node;
    }

    private void LoadSplitVolumesIfNeeded()
    {
        string inputDir = Path.GetDirectoryName(InputPath);
        SplitVolumes = new ClusterVolume[VolumeHeader.VolumeInfo.Length];

        for (int i = 0; i < VolumeHeader.VolumeInfo.Length; i++)
        {
            ClusterVolumeInfoMPH volEntry = VolumeHeader.VolumeInfo[i];
            string localPath = Path.Combine(inputDir, volEntry.FileName);
            if (!File.Exists(localPath))
            {
                Program.Log($"[!] Linked volume file '{volEntry.FileName}' not found, will be skipped");
                continue;
            }

            var vol = ClusterVolume.Read(localPath);
            if (vol is null)
            {
                Program.Log($"[!] Unable to read vol file '{localPath}'.");
                continue;
            }

            vol.Name = volEntry.FileName;
            SplitVolumes[i] = vol;
        }
    }

    public static bool DecryptHeader(Span<byte> data)
    {
        // Decrypt whole file
        ChaCha20 chacha20 = new ChaCha20(KeysetStore.GT7_Index_Key, KeysetStore.GT7_Index_IV, 0);

        // Love when libs don't support span
        chacha20.DecryptBytes(data, data.Length, 0);

        const uint BASE_CRC = 0xA7E4A1E8;
        uint crc = BASE_CRC;

        var ints = MemoryMarshal.Cast<byte, uint>(data);

        // Main header has another layer
        for (var i = 0; i < 0x800 / 4; i++)
        {
            uint value = ints[i];

            uint a = (byte)(crc >> 24);
            uint b = (byte)(crc >> 16);
            uint c = (byte)(crc >> 8);
            uint d = (byte)(crc >> 0);


            crc = value;

            value = CRC32.checksum_0x04C11DB7[a];
            value = value << 8 ^ CRC32.checksum_0x04C11DB7[b ^ (value >> 24)];
            value = value << 8 ^ CRC32.checksum_0x04C11DB7[c ^ (value >> 24)];
            value = value << 8 ^ CRC32.checksum_0x04C11DB7[d ^ (value >> 24)];
            value = ~(value ^ crc);

            ints[i] = value;
        }

        return true;
    }

    private SortedDictionary<string, MPHNodeInfo> RegisterFiles()
    {
        SortedDictionary<string, MPHNodeInfo> validFiles = [];

        if (File.Exists(Path.Combine("FileLists", "gt7_files.txt")))
        {
            Program.Log("[-] Mapping out files manually from GT7 files (gt7_files.txt)", forceConsolePrint: true);
            RegisterFromGT7Files(validFiles);
        }
        else
        {
            Program.Log("[!] gt7_files.txt not found, not using manual file list to map volume entries.", forceConsolePrint: true);
        }

        if (File.Exists(Path.Combine("FileLists", "gts_files.txt")))
        {
            Program.Log("[-] Mapping out files from GTS 1.68 files..", forceConsolePrint: true);
            RegisterFromGTSFiles(validFiles);
        }
        else
        {
            Program.Log("[!] gts_files.txt not found, not using GTS file list to map entries.", forceConsolePrint: true);
        }

        Program.Log("[-] Bruteforcing files...");
        MPHFileListBruteforcer bruteforcer = new MPHFileListBruteforcer(this);
        bruteforcer.BruteforceFindFiles(validFiles);

        return validFiles;
    }

    private SortedDictionary<string, MPHNodeInfo> RegisterFromGT7Files(SortedDictionary<string, MPHNodeInfo> validFiles)
    {
        var gt7Files = File.ReadAllLines(Path.Combine("FileLists", "gt7_files.txt"));

        foreach (var p in gt7Files)
        {
            if (string.IsNullOrEmpty(p) || p.StartsWith("//"))
                continue;

            if (p.StartsWith("dmsdata", StringComparison.OrdinalIgnoreCase))
            {
                CheckFile(validFiles, p + ".gpb");

                foreach (var entryName in _dmsEntryList)
                    CheckFile(validFiles, p + "/" + entryName);
            }
            else if (p.StartsWith("piece/4k/face/"))
            {
                // For MsgFaces
                for (var i = 0; i < 20; i++)
                {
                    CheckFile(validFiles, string.Format(p, "", i.ToString().PadLeft(2, '0')));
                    CheckFile(validFiles, string.Format(p, "Notify_", i.ToString().PadLeft(2, '0')));
                    CheckFile(validFiles, string.Format(p, "Caution_", i.ToString().PadLeft(2, '0')));
                    CheckFile(validFiles, string.Format(p, "Message_", i.ToString().PadLeft(2, '0')));
                    CheckFile(validFiles, string.Format(p, "Narration_", i.ToString().PadLeft(2, '0')));
                    CheckFile(validFiles, string.Format(p, "MessageL_", i.ToString().PadLeft(2, '0')));
                    CheckFile(validFiles, string.Format(p, "CenterNotify_", i.ToString().PadLeft(2, '0')));
                    CheckFile(validFiles, string.Format(p, "MenuBookStart", i.ToString().PadLeft(2, '0')));
                    CheckFile(validFiles, string.Format(p, "MessageNoTint", i.ToString().PadLeft(2, '0')));
                }

                continue;
            }

            CheckFile(validFiles, p);
        }

        return validFiles;
    }

    private SortedDictionary<string, MPHNodeInfo> RegisterFromGTSFiles(SortedDictionary<string, MPHNodeInfo> validFiles)
    {
        var gtsFiles = File.ReadAllLines(Path.Combine("FileLists", "gts_files.txt"));

        foreach (var p in gtsFiles)
        {
            var lower = p.ToLower();

            CheckFile(validFiles, lower);

            if (lower.Contains("gt7sp"))
                lower = lower.Replace("gt7sp", "gt7");

            CheckFile(validFiles, lower);

            if (lower.Contains(".adc"))
                lower = lower.Replace(".adc", ".mpackage");

            CheckFile(validFiles, lower);
        }

        return validFiles;
    }

    /// <summary>
    /// Used for PS5/PFS style volumes
    /// </summary>
    /// <param name="seed"></param>
    /// <returns></returns>
    public static string GetCacheKey(uint seed)
    {
        const string Alphabet = "P6MH85C24L91ZTIYURQ7NKJ0OSBWDAVGX3FE";
        char[] str =
        [
            Alphabet[(int)(seed % 36)],
            '/',
            Alphabet[(int)(seed / 36 % 36)],
            '/',
            Alphabet[seed > 0x81BF0FFF ? 1 : 0],
            Alphabet[(int)(seed / 0x39AA400 - 36 * ((57 * (seed / 0x39AA400)) >> 11))],
            Alphabet[(int)(seed / 0x19A100 % 36)],
            Alphabet[(int)(seed / 0xB640 % 36)],
            Alphabet[(int)(seed / 0x510 % 36)],
        ];
        return new string(str);
    }

    public void Dispose()
    {
        ((IDisposable)MainStream)?.Dispose();
        if (SplitVolumes is not null)
        {
            foreach (var vol in SplitVolumes)
                vol?.Dispose();
        }
    }
}
