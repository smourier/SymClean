using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.IO.MemoryMappedFiles;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;

namespace SymClean
{
    class Program
    {
        private static readonly string[] _binariesExtensions = new[] { ".dll", ".exe", ".sys", ".cpl", ".scr", ".ocx", ".ax", ".acm" };

        static void Main(string[] args)
        {
            Console.WriteLine("SymClean - Copyright (C) 2020-" + DateTime.Now.Year + " Simon Mourier. All rights reserved.");
            Console.WriteLine();
            if (CommandLine.HelpRequested || args.Length < 1)
            {
                Help();
                return;
            }

            var inputDirectoryPath = CommandLine.GetArgument<string>(0);
            if (inputDirectoryPath == null)
            {
                Help();
                return;
            }

#if DEBUG
            var testMode = CommandLine.GetArgument("testMode", true);
#else
            var testMode = CommandLine.GetArgument("testMode", false);
#endif
            Console.WriteLine("Test Mode: " + testMode);
            var totalLength = 0L;

            // scan windows
            var binariesDic = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
            foreach (var searchPath in BinariesPaths)
            {
                foreach (var file in Win32FindData.EnumerateFileSystemEntries(searchPath, Win32FindDataEnumerateOptions.Recursive))
                {
                    if (!_binariesExtensions.Contains(file.Extension))
                        continue;

                    if (!binariesDic.TryGetValue(file.Name, out var list))
                    {
                        list = new List<string>();
                        binariesDic[file.Name] = list;
                    }

                    list.Add(file.FullName);
                }
            }
            Console.WriteLine("Number of detected binaries: " + binariesDic.Count);

            foreach (var directory in Directory.EnumerateDirectories(inputDirectoryPath))
            {
                if (!Path.GetExtension(directory).EqualsIgnoreCase(".pdb"))
                    continue;

                var pdbDirs = new List<PdbDir>();
                foreach (var idir in Directory.EnumerateDirectories(directory))
                {
                    var pdbDir = new PdbDir();
                    pdbDir.Path = idir;

                    // https://randomascii.wordpress.com/2013/03/09/symbols-the-microsoft-way/
                    var name = Path.GetFileName(idir);
                    if (name.Length < 32)
                        continue;

                    var sguid = name.Substring(0, 32);
                    if (!Guid.TryParse(sguid, out var guid))
                        continue;

                    pdbDir.Guid = guid;
                    pdbDir.Age = int.Parse(name.Substring(32), NumberStyles.HexNumber);
                    pdbDirs.Add(pdbDir);
                }

                if (pdbDirs.Count == 0)
                    continue;

                // find the binaries by name
                var binaryName = pdbDirs[0].BinaryName;
                List<string> list = null;
                foreach (var ext in _binariesExtensions)
                {
                    if (binariesDic.TryGetValue(binaryName + ext, out list))
                        break;
                }

                if (list == null)
                {
                    Console.WriteLine("No matching file (" + string.Join(", ", _binariesExtensions) + ") found for binary '" + binaryName + "'.");
                }

                // removing matching pdb from the list
                if (list != null)
                {
                    foreach (var sp in list)
                    {
                        var info = PdbInfo.Extract(sp);
                        if (info != null)
                        {
                            //Console.WriteLine("Matching file found for binary '" + binaryName + "': " + info);
                            var pdbDir = pdbDirs.FirstOrDefault(p => p.Age == info.Age && p.Guid == info.Guid);
                            if (pdbDir != null)
                            {
                                pdbDirs.Remove(pdbDir);
                            }
                        }
                    }
                }

                // left pdbs must be delete
                foreach (var pdbDir in pdbDirs)
                {
                    // a pdb dir doesn't always contain a pdb
                    var length = GetDirectoryLength(pdbDir.Path);
                    Console.WriteLine("Removing pdb: " + pdbDir + " length: " + length);
                    totalLength += length;

                    if (!testMode)
                    {
                        try
                        {
                            Directory.Delete(pdbDir.Path, true);
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine("An error occurred trying to delete directory '" + pdbDir.Path + "': " + e.Message);
                        }
                    }
                }
            }

            Console.WriteLine("Total removed length: " + totalLength);
        }

        private static IEnumerable<string> BinariesPaths
        {
            get
            {
                yield return Environment.GetFolderPath(Environment.SpecialFolder.Windows);
                yield return Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
                yield return Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
            }
        }

        private static long GetDirectoryLength(string path)
        {
            var length = 0L;
            foreach (var file in Win32FindData.EnumerateFileSystemEntries(path, Win32FindDataEnumerateOptions.Recursive))
            {
                length += file.Length;
            }
            return length;
        }

        private class PdbDir
        {
            public int Age;
            public Guid Guid;
            public string Path;
            public string BinaryName => System.IO.Path.GetFileNameWithoutExtension(System.IO.Path.GetDirectoryName(Path));

            public override string ToString() => Age + ":" + Guid + ":" + Path;
        }

        private class PdbInfo
        {
            public int Age;
            public Guid Guid;
            public string Path;
            public override string ToString() => Age + ":" + Guid + ":" + Path;

            public static PdbInfo Extract(string path)
            {
                if (path == null)
                    throw new ArgumentNullException(nameof(path));

                const ushort IMAGE_DIRECTORY_ENTRY_DEBUG = 6;
                using var file = MemoryMappedFile.CreateFromFile(path, FileMode.Open, null, 0, MemoryMappedFileAccess.Read);
                using var accessor = file.CreateViewAccessor(0, 0, MemoryMappedFileAccess.Read);
                var basePtr = accessor.SafeMemoryMappedViewHandle.DangerousGetHandle();
                var ptr = ImageDirectoryEntryToData(basePtr, false, IMAGE_DIRECTORY_ENTRY_DEBUG, out var size);
                if (ptr == IntPtr.Zero)
                    return null;

                var dir = Marshal.PtrToStructure<IMAGE_DEBUG_DIRECTORY>(ptr);
                const int IMAGE_DEBUG_TYPE_CODEVIEW = 2;
                if (dir.Type == IMAGE_DEBUG_TYPE_CODEVIEW)
                {
                    var ntHeadersPtr = ImageNtHeader(basePtr);
                    var dbgPtr = ImageRvaToVa(ntHeadersPtr, basePtr, dir.AddressOfRawData, IntPtr.Zero);

                    //struct CV_INFO_PDB70
                    //{
                    //  DWORD     Signature;
                    //  BYTE      Guid[16];
                    //  DWORD     Age;
                    //  char      PdbFileName[1];
                    //};

                    if (dbgPtr != IntPtr.Zero)
                    {
                        var sig = Marshal.ReadInt32(dbgPtr);
                        if (sig == 0x53445352) // "RSDS"
                        {
                            var bytes = new byte[16];
                            for (var i = 0; i < bytes.Length; i++)
                            {
                                bytes[i] = Marshal.ReadByte(dbgPtr, 4 + i);
                            }

                            var pdbFile = new PdbInfo();
                            pdbFile.Guid = new Guid(bytes);
                            pdbFile.Age = Marshal.ReadInt32(dbgPtr, 4 + 16);
                            pdbFile.Path = path;
                            return pdbFile;
                        }
                    }
                }
                return null;
            }
        }

        static void Help()
        {
            Console.WriteLine(Assembly.GetEntryAssembly().GetName().Name.ToUpperInvariant() + " <symbols directory path>");
            Console.WriteLine();
            Console.WriteLine("Description:");
            Console.WriteLine("    This tool is used to clean a Windows symbols (.pdb) directory and remove .pdb files that do not correspond to binaries files on the system.");
            Console.WriteLine();
            Console.WriteLine("Example:");
            Console.WriteLine();
            Console.WriteLine("    " + Assembly.GetEntryAssembly().GetName().Name.ToUpperInvariant() + " d:\\symbols");
            Console.WriteLine();
            Console.WriteLine("    Cleans the d:\\symbols directory.");
            Console.WriteLine();
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IMAGE_DEBUG_DIRECTORY
        {
            public uint Characteristics;
            public uint TimeDateStamp;
            public ushort MajorVersion;
            public ushort MinorVersion;
            public uint Type;
            public uint SizeOfData;
            public int AddressOfRawData;
            public uint PointerToRawData;
        }

        [DllImport("dbghelp")]
        private static extern IntPtr ImageDirectoryEntryToData(IntPtr Base, bool MappedAsImage, ushort DirectoryEntry, out int Size);

        [DllImport("dbghelp")]
        private static extern IntPtr ImageRvaToVa(IntPtr NtHeaders, IntPtr Base, int rva, IntPtr LastRvaSection);

        [DllImport("dbghelp")]
        private static extern IntPtr ImageNtHeader(IntPtr Base);
    }
}
