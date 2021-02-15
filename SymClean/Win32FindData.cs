using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;

namespace SymClean
{
    public sealed class Win32FindData
    {
        private Win32FindData()
        {
        }

        public string FullName { get; private set; }
        public long Length { get; private set; }
        public FileAttributes Attributes { get; private set; }
        public DateTime CreationTimeUtc { get; private set; }
        public DateTime LastAccessTimeUtc { get; private set; }
        public DateTime LastWriteTimeUtc { get; private set; }

        public DateTime LastWriteTime
        {
            get
            {
                if (LastAccessTimeUtc == DateTime.MinValue)
                    return DateTime.MinValue;

                return LastWriteTimeUtc.ToLocalTime();
            }
        }

        public DateTime CreationTime
        {
            get
            {
                if (CreationTimeUtc == DateTime.MinValue)
                    return DateTime.MinValue;

                return CreationTimeUtc.ToLocalTime();
            }
        }

        public DateTime LastAccessTime
        {
            get
            {
                if (LastAccessTimeUtc == DateTime.MinValue)
                    return DateTime.MinValue;

                return LastAccessTimeUtc.ToLocalTime();
            }
        }

        public string Name
        {
            get
            {
                if (FullName == null)
                    return string.Empty; // never null

                return Path.GetFileName(FullName);
            }
        }

        public string NameWithoutExtension
        {
            get
            {
                if (FullName == null)
                    return string.Empty; // never null

                return Path.GetFileNameWithoutExtension(FullName);
            }
        }

        public string Extension
        {
            get
            {
                if (FullName == null)
                    return string.Empty; // never null

                return Path.GetExtension(FullName).ToLowerInvariant();
            }
        }

        public bool IsDirectory => (Attributes & FileAttributes.Directory) == FileAttributes.Directory;
        public override string ToString() => FullName;

        public bool HasExtension(string extension) => HasExtension(new string[] { extension });
        public bool HasExtension(params string[] extensions) => HasExtension((IEnumerable<string>)extensions);
        public bool HasExtension(IEnumerable<string> extensions)
        {
            if (extensions == null)
                return false;

            var ext = Extension;
            foreach (var extension in extensions)
            {
                if (extension == null)
                    continue;

                if (string.Compare(extension, ext, StringComparison.OrdinalIgnoreCase) == 0)
                    return true;
            }
            return false;
        }

        public static Win32FindData FromPath(string path)
        {
            if (path == null)
                throw new ArgumentNullException(nameof(path));

            var di = new DirectoryInfo(path);
            if (di.Exists)
            {
                var dir = new Win32FindData();
                dir.Attributes = di.Attributes;
                dir.CreationTimeUtc = di.CreationTimeUtc;
                dir.FullName = di.FullName;
                dir.LastAccessTimeUtc = di.LastAccessTimeUtc;
                dir.LastWriteTimeUtc = di.LastWriteTimeUtc;
                return dir;
            }

            var fi = new FileInfo(path);
            if (fi.Exists)
            {
                var file = new Win32FindData();
                file.Attributes = fi.Attributes;
                file.CreationTimeUtc = fi.CreationTimeUtc;
                file.FullName = fi.FullName;
                file.LastAccessTimeUtc = fi.LastAccessTimeUtc;
                file.LastWriteTimeUtc = fi.LastWriteTimeUtc;
                file.Length = fi.Length;
                return file;
            }
            return null;
        }

        public static IEnumerable<Win32FindData> EnumerateFileSystemEntries(string directoryPath, Win32FindDataEnumerateOptions options = Win32FindDataEnumerateOptions.None, bool throwOnError = false)
        {
            if (directoryPath == null)
                throw new ArgumentNullException(nameof(directoryPath));

            if (!Path.IsPathRooted(directoryPath))
            {
                directoryPath = Path.GetFullPath(directoryPath);
            }

            return PrivateEnumerateFileSystemEntries(directoryPath, options, throwOnError);
        }

        private static IEnumerable<Win32FindData> PrivateEnumerateFileSystemEntries(string directoryPath, Win32FindDataEnumerateOptions options, bool throwOnError)
        {
            if (!Directory.Exists(directoryPath))
                yield break;

            var findPath = Normalize(directoryPath, true);
            if (!findPath.EndsWith("*"))
            {
                findPath = Path.Combine(findPath, "*");
            }

            var h = FindFirstFile(findPath, out WIN32_FIND_DATA data);
            if (h == INVALID_HANDLE_VALUE)
            {
                if (throwOnError)
                    throw new Win32Exception(Marshal.GetLastWin32Error());

                yield break;
            }

            var recursive = (options & Win32FindDataEnumerateOptions.Recursive) == Win32FindDataEnumerateOptions.Recursive;

            if (Include(ref data))
            {
                yield return ToWin32FindData(data, directoryPath);
                if (recursive && (data.fileAttributes & FileAttributes.Directory) == FileAttributes.Directory)
                {
                    foreach (Win32FindData wfd in PrivateEnumerateFileSystemEntries(Path.Combine(directoryPath, data.cFileName), options, false))
                    {
                        yield return wfd;
                    }
                }
            }
            do
            {
                if (!FindNextFile(h, out data))
                {
                    if (Marshal.GetLastWin32Error() == ERROR_NO_MORE_FILES)
                    {
                        FindClose(h);
                        break;
                    }
                    continue;
                }

                if (Include(ref data))
                {
                    yield return ToWin32FindData(data, directoryPath);
                    if (recursive && (data.fileAttributes & FileAttributes.Directory) == FileAttributes.Directory)
                    {
                        foreach (Win32FindData wfd in PrivateEnumerateFileSystemEntries(Path.Combine(directoryPath, data.cFileName), options, false))
                        {
                            yield return wfd;
                        }
                    }
                }
            }
            while (true);
        }

        public static void EnumerateFileSystemEntries(string directoryPath, EventHandler<Win32FindDataEventArgs> foundFunction) => EnumerateFileSystemEntries(directoryPath, Win32FindDataEnumerateOptions.Recursive, true, foundFunction);
        public static void EnumerateFileSystemEntries(string directoryPath, Win32FindDataEnumerateOptions options, EventHandler<Win32FindDataEventArgs> foundFunction)
        {
            if (directoryPath == null)
                throw new ArgumentNullException(nameof(directoryPath));

            if (foundFunction == null)
                throw new ArgumentNullException(nameof(foundFunction));

            EnumerateFileSystemEntries(directoryPath, options, true, foundFunction);
        }

        private static string Normalize(string path, bool expandEnvironmentVariables)
        {
            if (path == null)
                return null;

            string expanded;
            if (expandEnvironmentVariables)
            {
                expanded = Environment.ExpandEnvironmentVariables(path);
            }
            else
            {
                expanded = path;
            }

            if (expanded.StartsWith(_prefix))
                return expanded;

            if (expanded.StartsWith(@"\\"))
                return _uncPrefix + expanded.Substring(2);

            return _prefix + expanded;
        }

        private static bool EnumerateFileSystemEntries(string directoryPath, Win32FindDataEnumerateOptions options, bool throwOnError, EventHandler<Win32FindDataEventArgs> foundFunction)
        {
            directoryPath = Path.GetFullPath(directoryPath);

            if (!Directory.Exists(directoryPath))
                return true;

            var findPath = Normalize(directoryPath, true);
            if (!findPath.EndsWith("*"))
            {
                findPath = Path.Combine(findPath, "*");
            }

            var h = FindFirstFile(findPath, out WIN32_FIND_DATA data);
            if (h == INVALID_HANDLE_VALUE)
            {
                if (throwOnError)
                    throw new Win32Exception(Marshal.GetLastWin32Error());

                return true;
            }

            if (!HandleFileSystemEntry(ref data, directoryPath, options, foundFunction))
            {
                FindClose(h);
                return false;
            }

            do
            {
                if (!FindNextFile(h, out data))
                {
                    if (Marshal.GetLastWin32Error() == ERROR_NO_MORE_FILES)
                    {
                        FindClose(h);
                        return true;
                    }
                    continue;
                }

                if (!HandleFileSystemEntry(ref data, directoryPath, options, foundFunction))
                {
                    FindClose(h);
                    return false;
                }
            }
            while (true);
        }

        private static bool HandleFileSystemEntry(ref WIN32_FIND_DATA data, string directoryPath, Win32FindDataEnumerateOptions options, EventHandler<Win32FindDataEventArgs> foundFunction)
        {
            if (!Include(ref data))
                return true;

            var depthFirst = (options & Win32FindDataEnumerateOptions.DepthFirst) == Win32FindDataEnumerateOptions.DepthFirst;
            if (!depthFirst)
            {
                var e = new Win32FindDataEventArgs(ToWin32FindData(data, directoryPath));
                foundFunction(directoryPath, e);
                if (e.Cancel)
                    return false;
            }

            var recursive = (options & Win32FindDataEnumerateOptions.Recursive) == Win32FindDataEnumerateOptions.Recursive;
            if (recursive && (data.fileAttributes & FileAttributes.Directory) == FileAttributes.Directory)
            {
                if (!EnumerateFileSystemEntries(Path.Combine(directoryPath, data.cFileName), options, false, foundFunction))
                    return false;
            }

            if (depthFirst)
            {
                var e = new Win32FindDataEventArgs(ToWin32FindData(data, directoryPath));
                foundFunction(directoryPath, e);
                if (e.Cancel)
                    return false;
            }
            return true;
        }

        private static bool Include(ref WIN32_FIND_DATA data) => data.cFileName != "." && data.cFileName != "..";

        private static Win32FindData ToWin32FindData(WIN32_FIND_DATA data, string directoryPath)
        {
            var fd = new Win32FindData();
            fd.Attributes = data.fileAttributes;
            fd.CreationTimeUtc = DateTimeFromFileTimeUtc(data.ftCreationTimeHigh, data.ftCreationTimeLow);
            fd.LastAccessTimeUtc = DateTimeFromFileTimeUtc(data.ftLastAccessTimeHigh, data.ftLastAccessTimeLow);
            fd.LastWriteTimeUtc = DateTimeFromFileTimeUtc(data.ftLastWriteTimeHigh, data.ftLastWriteTimeLow);
            fd.FullName = Path.Combine(directoryPath, data.cFileName);
            fd.Length = data.fileSizeLow | ((long)data.fileSizeHigh << 32);
            return fd;
        }

        private static DateTime DateTimeFromFileTimeUtc(uint hi, uint lo)
        {
            try
            {
                var time = ((long)hi << 32) | lo;
                return DateTime.FromFileTimeUtc(time);
            }
            catch
            {
                return DateTime.MinValue;
            }
        }

        [DllImport("Kernel32", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr FindFirstFile(string lpFileName, out WIN32_FIND_DATA lpFindFileData);

        [DllImport("Kernel32", SetLastError = true)]
        private static extern bool FindClose(IntPtr hFindFile);

        [DllImport("Kernel32", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool FindNextFile(IntPtr hFindFile, out WIN32_FIND_DATA lpFindFileData);

#pragma warning disable IDE1006 // Naming Styles
        private const int ERROR_NO_MORE_FILES = 18;
        private static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
#pragma warning restore IDE1006 // Naming Styles
        private const string _prefix = @"\\?\";
        private const string _uncPrefix = _prefix + @"UNC\";

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WIN32_FIND_DATA
        {
            public FileAttributes fileAttributes;
            public uint ftCreationTimeLow;
            public uint ftCreationTimeHigh;
            public uint ftLastAccessTimeLow;
            public uint ftLastAccessTimeHigh;
            public uint ftLastWriteTimeLow;
            public uint ftLastWriteTimeHigh;
            public uint fileSizeHigh;
            public uint fileSizeLow;
            public uint dwReserved0;
            public uint dwReserved1;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string cFileName;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 14)]
            public string cAlternateFileName;
        }
    }
}
