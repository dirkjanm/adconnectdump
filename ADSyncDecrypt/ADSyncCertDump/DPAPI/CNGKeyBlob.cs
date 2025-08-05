using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using Shwmae;

namespace DPAPI {

    public enum KeySource {
        Normal,
        WinHello
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    struct CNGPropertyHeader {
        public uint Length;
        public uint Type;
        public uint Unknown;
        public uint NameLen;
        public uint PropertyLen;
    }

    public struct CNGProperty {

        public uint Type;
        public string Name;
        public byte[] Value;

        public static List<CNGProperty> Parse(BinaryReader br, uint propsLen) {

            var props = new List<CNGProperty>();
            var startingOffset = br.BaseStream.Position;

            while (br.BaseStream.Position - startingOffset < propsLen) {
                var lastOffset = br.BaseStream.Position;
                var hdr = br.ReadStruct<CNGPropertyHeader>();
                props.Add(new CNGProperty() {
                    Type = hdr.Type,
                    Name = Encoding.Unicode.GetString(br.ReadBytes((int)hdr.NameLen)),
                    Value = br.ReadBytes((int)hdr.PropertyLen)
                });
                br.BaseStream.Position = lastOffset + hdr.Length;
            }

            return props;
        }
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    struct CNGKeyHeader {
        public uint Version;
        public uint Unknown1;
        public uint NameLen;
        public uint Type;
        public uint PublicPropertiesLen;
        public uint PrivatePropertiesLen;
        public uint PrivateKeyLen;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] Unknown2;
    }

    public class CNGKeyBlob {
        public string Name;
        public List<CNGProperty> PublicProperties;
        public DPAPI_BLOB PrivateProperties;
        public byte[] PrivatePropertiesBytes;
        public DPAPI_BLOB PrivateKey;
        public byte[] PrivateKeyBytes;

        public static CNGKeyBlob Parse(string fileName) {
            return Parse(new BinaryReader(new FileStream(fileName, FileMode.Open, FileAccess.Read)));
        }

        public static CNGKeyBlob Find(string guid) {
            return Find(guid, Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Microsoft\\Crypto\\Keys"));
        }

        public static CNGKeyBlob Find(string guid, string basePath) {

            var files = Directory.EnumerateFiles(basePath);

            foreach(var file in files) {
                var blob = Parse(file);
                if(blob.Name == guid) {
                    return blob;
                }               
            }

            return null;
        }

        public static CNGKeyBlob Parse(BinaryReader br) {
            var hdr = br.ReadStruct<CNGKeyHeader>();
            return new CNGKeyBlob {
                Name = Encoding.Unicode.GetString(br.ReadBytes((int)hdr.NameLen)),
                PublicProperties = CNGProperty.Parse(br, hdr.PublicPropertiesLen),
                PrivatePropertiesBytes = br.ReadBytes((int)hdr.PrivatePropertiesLen),
                PrivateKeyBytes = br.ReadBytes((int)hdr.PrivateKeyLen)
            };
        }

        public T GetProperty<T>(string name) {

            var prop = PublicProperties.FirstOrDefault(p => p.Name == name);

            if (prop.Equals(default(CNGProperty))) {
                return default;
            }

            if (typeof(T) == typeof(string)) {
                if (prop.Type == 0x20)
                    return (T)Convert.ChangeType(Encoding.Unicode.GetString(prop.Value), typeof(T));
                else
                    return (T)Convert.ChangeType(prop.Value.Hex(), typeof(T));
            } else if (prop.Type == 0) {
                var value = BitConverter.ToInt64(prop.Value, 0);
                if (typeof(T) == typeof(DateTime))
                    return (T)Convert.ChangeType(DateTime.FromFileTimeUtc(value), typeof(T));
                else
                    return (T)Convert.ChangeType(value, typeof(T));
            } else {
                throw new ArgumentException($"Cannot convert property with name {name} to type {typeof(T).Name}");
            }
        }
    }

    public class CNGKey {
        public CNGKeyBlob KeyBlob;
        public ushort PinLength;
    }
}
