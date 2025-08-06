using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace Shwmae {
    internal static class BinaryReaderUtils {

        public static T ReadStruct<T>(this BinaryReader br) {
            int structSize = Marshal.SizeOf(typeof(T));
            var structBytes = br.ReadBytes(structSize);
            var gcHandle = GCHandle.Alloc(structBytes, GCHandleType.Pinned);
            var result = Marshal.PtrToStructure<T>(gcHandle.AddrOfPinnedObject());
            gcHandle.Free();
            return result;
        }

        public static string ReadIntPrefixedString(this BinaryReader br) {
            return Encoding.Unicode.GetString(br.ReadBytes(br.ReadInt32()));
        }
    }
}
