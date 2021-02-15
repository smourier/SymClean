using System;

namespace SymClean
{
    [Flags]
    public enum Win32FindDataEnumerateOptions
    {
        None = 0x0,
        Recursive = 0x1,
        DepthFirst = 0x2,
        DontOverwriteIfExists = 0x4,
        DontOverwriteIfIdentical = 0x8,
        DontOverwriteIfNewer = 0x10,
    }
}
