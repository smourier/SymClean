using System.ComponentModel;

namespace SymClean
{
    public class Win32FindDataEventArgs : CancelEventArgs
    {
        public Win32FindDataEventArgs(Win32FindData entry)
        {
            Entry = entry;
        }

        public Win32FindData Entry { get; }
    }
}
