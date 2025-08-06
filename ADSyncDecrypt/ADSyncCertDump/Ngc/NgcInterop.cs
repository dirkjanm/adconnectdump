using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Shwmae.Ngc {

    [Flags]
    public enum NCryptEncryptFlags {
        None = 0,
        NCRYPT_NO_PADDING_FLAG = 1,
        NCRYPT_PAD_PKCS1_FLAG = 2,
        NCRYPT_PAD_OAEP_FLAG = 4,
        NCRYPT_SILENT_FLAG = 0x40,
        NCRYPT_SEALING_FLAG = 0x100
    }

    public enum SECURITY_STATUS : uint {
        /// <summary>
        /// The operation completed successfully.
        /// </summary>
        ERROR_SUCCESS = 0,

        /// <summary>Bad UID.</summary>
        NTE_BAD_UID = 0x80090001,

        /// <summary>Bad hash.</summary>
        NTE_BAD_HASH = 0x80090002,

        /// <summary>Bad key.</summary>
        NTE_BAD_KEY = 0x80090003,

        /// <summary>Bad length.</summary>
        NTE_BAD_LEN = 0x80090004,

        /// <summary>Bad data.</summary>
        NTE_BAD_DATA = 0x80090005,

        /// <summary>Invalid signature.</summary>
        NTE_BAD_SIGNATURE = 0x80090006,

        /// <summary>Bad version of provider.</summary>
        NTE_BAD_VER = 0x80090007,

        /// <summary>Invalid algorithm specified.</summary>
        NTE_BAD_ALGID = 0x80090008,

        /// <summary>Invalid flags specified.</summary>
        NTE_BAD_FLAGS = 0x80090009,

        /// <summary>Invalid type specified.</summary>
        NTE_BAD_TYPE = 0x8009000A,

        /// <summary>Key not valid for use in specified state.</summary>
        NTE_BAD_KEY_STATE = 0x8009000B,

        /// <summary>Hash not valid for use in specified state.</summary>
        NTE_BAD_HASH_STATE = 0x8009000C,

        /// <summary>Key does not exist.</summary>
        NTE_NO_KEY = 0x8009000D,

        /// <summary>Insufficient memory available for the operation.</summary>
        NTE_NO_MEMORY = 0x8009000E,

        /// <summary>Object already exists.</summary>
        NTE_EXISTS = 0x8009000F,

        /// <summary>Access denied.</summary>
        NTE_PERM = 0x80090010,

        /// <summary>Object was not found.</summary>
        NTE_NOT_FOUND = 0x80090011,

        /// <summary>Data already encrypted.</summary>
        NTE_DOUBLE_ENCRYPT = 0x80090012,

        /// <summary>Invalid provider specified.</summary>
        NTE_BAD_PROVIDER = 0x80090013,

        /// <summary>Invalid provider type specified.</summary>
        NTE_BAD_PROV_TYPE = 0x80090014,

        /// <summary>Invalid provider public key.</summary>
        NTE_BAD_PUBLIC_KEY = 0x80090015,

        /// <summary>Keyset does not exist</summary>
        NTE_BAD_KEYSET = 0x80090016,

        /// <summary>Provider type not defined.</summary>
        NTE_PROV_TYPE_NOT_DEF = 0x80090017,

        /// <summary>Invalid registration for provider type.</summary>
        NTE_PROV_TYPE_ENTRY_BAD = 0x80090018,

        /// <summary>The keyset not defined.</summary>
        NTE_KEYSET_NOT_DEF = 0x80090019,

        /// <summary>Invalid keyset registration.</summary>
        NTE_KEYSET_ENTRY_BAD = 0x8009001A,

        /// <summary>Provider type does not match registered value.</summary>
        NTE_PROV_TYPE_NO_MATCH = 0x8009001B,

        /// <summary>Corrupt digital signature file.</summary>
        NTE_SIGNATURE_FILE_BAD = 0x8009001C,

        /// <summary>Provider DLL failed to initialize correctly.</summary>
        NTE_PROVIDER_DLL_FAIL = 0x8009001D,

        /// <summary>Provider DLL not found.</summary>
        NTE_PROV_DLL_NOT_FOUND = 0x8009001E,

        /// <summary>Invalid keyset parameter.</summary>
        NTE_BAD_KEYSET_PARAM = 0x8009001F,

        /// <summary>Internal error occurred.</summary>
        NTE_FAIL = 0x80090020,

        /// <summary>Base error occurred.</summary>
        NTE_SYS_ERR = 0x80090021,

        /// <summary>The buffer supplied to a function was too small.</summary>
        NTE_BUFFER_TOO_SMALL = 0x80090028,

        /// <summary>The requested operation is not supported.</summary>
        NTE_NOT_SUPPORTED = 0x80090029,

        /// <summary>No more data is available.</summary>
        NTE_NO_MORE_ITEMS = 0x8009002a,

        /// <summary>Provider could not perform the action since the context was acquired as silent.</summary>
        NTE_SILENT_CONTEXT = 0x80090022,

        /// <summary>The security token does not have storage space available for an additional container.</summary>
        NTE_TOKEN_KEYSET_STORAGE_FULL = 0x80090023,

        /// <summary>The profile for the user is a temporary profile.</summary>
        NTE_TEMPORARY_PROFILE = 0x80090024,

        /// <summary>The key parameters could not be set because the CSP uses fixed parameters.</summary>
        NTE_FIXEDPARAMETER = 0x80090025,

        /// <summary>The supplied handle is invalid.</summary>
        NTE_INVALID_HANDLE = 0x80090026,

        /// <summary>The parameter is incorrect.</summary>
        NTE_INVALID_PARAMETER = 0x80090027,

        /// <summary>The supplied buffers overlap incorrectly.</summary>
        NTE_BUFFERS_OVERLAP = 0x8009002B,

        /// <summary>The specified data could not be decrypted.</summary>
        NTE_DECRYPTION_FAILURE = 0x8009002C,

        /// <summary>An internal consistency check failed.</summary>
        NTE_INTERNAL_ERROR = 0x8009002D,

        /// <summary>This operation requires input from the user.</summary>
        NTE_UI_REQUIRED = 0x8009002E,

        /// <summary>The cryptographic provider does not support HMAC.</summary>
        NTE_HMAC_NOT_SUPPORTED = 0x8009002F,

        /// <summary>The device that is required by this cryptographic provider is not ready for use.</summary>
        NTE_DEVICE_NOT_READY = 0x80090030,

        /// <summary>The dictionary attack mitigation is triggered and the provided authorization was ignored by the provider.</summary>
        NTE_AUTHENTICATION_IGNORED = 0x80090031,

        /// <summary>The validation of the provided data failed the integrity or signature validation.</summary>
        NTE_VALIDATION_FAILED = 0x80090032,

        /// <summary>Incorrect password.</summary>
        NTE_INCORRECT_PASSWORD = 0x80090033,

        /// <summary>Encryption failed.</summary>
        NTE_ENCRYPTION_FAILURE = 0x80090034,

        /// <summary>The device that is required by this cryptographic provider is not found on this platform.</summary>
        NTE_DEVICE_NOT_FOUND = 0x80090035,

        TPM_E_PCP_INVALID_PARAMETER = 0x80290403
    }

    public enum BufferType {
        /// <summary>
        /// The buffer is a key derivation function (KDF) parameter that contains a null-terminated Unicode string that identifies the hash algorithm. This can be one of the standard hash algorithm identifiers from CNG Algorithm Identifiers or the identifier for another registered hash algorithm.
        /// The size specified by the <see cref="NCryptBuffer.cbBuffer"/> member of this structure must include the terminating NULL character.
        /// </summary>
        KDF_HASH_ALGORITHM = 0,

        /// <summary>
        /// The buffer is a KDF parameter that contains the value to add to the beginning of the message that is input to the hash function.
        /// </summary>
        KDF_SECRET_PREPEND = 1,

        /// <summary>
        /// The buffer is a KDF parameter that contains the value to add to the end of the message that is input to the hash function.
        /// </summary>
        KDF_SECRET_APPEND = 2,

        /// <summary>
        /// The buffer is a KDF parameter that contains the plain text value of the HMAC key.
        /// </summary>
        KDF_HMAC_KEY = 3,

        /// <summary>
        /// The buffer is a KDF parameter that contains an ANSI string that contains the transport layer security (TLS) pseudo-random function (PRF) label.
        /// </summary>
        KDF_TLS_PRF_LABEL = 4,

        /// <summary>
        /// The buffer is a KDF parameter that contains the PRF seed value. The seed must be 64 bytes long.
        /// </summary>
        KDF_TLS_PRF_SEED = 5,

        /// <summary>
        /// The buffer is a KDF parameter that contains the secret agreement handle. The <see cref="NCryptBuffer.pvBuffer"/> member contains a BCRYPT_SECRET_HANDLE value and is not a pointer.
        /// </summary>
        KDF_SECRET_HANDLE = 6,

        /// <summary>
        /// The buffer is a KDF parameter that contains a DWORD value identifying the SSL/TLS protocol version whose PRF algorithm is to be used.
        /// </summary>
        KDF_TLS_PRF_PROTOCOL = 7,

        /// <summary>
        /// The buffer is a KDF parameter that contains the byte array to use as the AlgorithmID subfield of the OtherInfo parameter to the SP 800-56A KDF.
        /// </summary>
        KDF_ALGORITHMID = 8,

        /// <summary>
        /// The buffer is a KDF parameter that contains the byte array to use as the PartyUInfo subfield of the OtherInfo parameter to the SP 800-56A KDF.
        /// </summary>
        KDF_PARTYUINFO = 9,

        /// <summary>
        /// The buffer is a KDF parameter that contains the byte array to use as the PartyVInfo subfield of the OtherInfo parameter to the SP 800-56A KDF.
        /// </summary>
        KDF_PARTYVINFO = 10,

        /// <summary>
        /// The buffer is a KDF parameter that contains the byte array to use as the SuppPubInfo subfield of the OtherInfo parameter to the SP 800-56A KDF.
        /// </summary>
        KDF_SUPPPUBINFO = 11,

        /// <summary>
        /// The buffer is a KDF parameter that contains the byte array to use as the SuppPrivInfo subfield of the OtherInfo parameter to the SP 800-56A KDF.
        /// </summary>
        KDF_SUPPPRIVINFO = 12,

        KDF_LABEL = 13,

        KDF_CONTEXT = 14,

        KDF_SALT = 15,

        KDF_ITERATION_COUNT = 16,

        /// <summary>
        /// The buffer contains the random number of the SSL client.
        /// </summary>
        NCRYPTBUFFER_SSL_CLIENT_RANDOM = 20,

        /// <summary>
        /// The buffer contains the random number of the SSL server.
        /// </summary>
        NCRYPTBUFFER_SSL_SERVER_RANDOM = 21,

        /// <summary>
        /// The buffer contains the highest SSL version supported.
        /// </summary>
        NCRYPTBUFFER_SSL_HIGHEST_VERSION = 22,

        /// <summary>
        /// The buffer contains the clear portion of the SSL master key.
        /// </summary>
        NCRYPTBUFFER_SSL_CLEAR_KEY = 23,

        /// <summary>
        /// The buffer contains the SSL key argument data.
        /// </summary>
        NCRYPTBUFFER_SSL_KEY_ARG_DATA = 24,

        /// <summary>
        /// The buffer contains a null-terminated ANSI string that contains the PKCS object identifier.
        /// </summary>
        NCRYPTBUFFER_PKCS_OID = 40,

        /// <summary>
        /// The buffer contains a null-terminated ANSI string that contains the PKCS algorithm object identifier.
        /// </summary>
        NCRYPTBUFFER_PKCS_ALG_OID = 41,

        /// <summary>
        /// The buffer contains the PKCS algorithm parameters.
        /// </summary>
        NCRYPTBUFFER_PKCS_ALG_PARAM = 42,

        /// <summary>
        /// The buffer contains the PKCS algorithm identifier.
        /// </summary>
        NCRYPTBUFFER_PKCS_ALG_ID = 43,

        /// <summary>
        /// The buffer contains the PKCS attributes.
        /// </summary>
        NCRYPTBUFFER_PKCS_ATTRS = 44,

        /// <summary>
        /// The buffer contains a null-terminated Unicode string that contains the key name.
        /// </summary>
        NCRYPTBUFFER_PKCS_KEY_NAME = 45,

        /// <summary>
        /// The buffer contains a null-terminated Unicode string that contains the PKCS8 password. This parameter is optional and can be NULL.
        /// </summary>
        NCRYPTBUFFER_PKCS_SECRET = 46,

        /// <summary>
        /// The buffer contains a serialized certificate store that contains the PKCS certificate. This serialized store is obtained by using the CertSaveStore function with the CERT_STORE_SAVE_TO_MEMORY option. When this property is being retrieved, you can access the certificate store by passing this serialized store to the CertOpenStore function with the CERT_STORE_PROV_SERIALIZED option.
        /// </summary>
        NCRYPTBUFFER_CERT_BLOB = 47,
    }

    public unsafe partial struct NCryptBufferDesc {
        public const uint NCRYPTBUFFER_VERSION = 0;
        public const int NCRYPTBUFFER_EMPTY = 0;

        /// <summary>
        /// The version number of the structure. Currently, this member must be set to <see cref="NCRYPTBUFFER_VERSION"/>.
        /// </summary>
        public uint ulVersion;

        /// <summary>
        /// The number of elements in the <see cref="pBuffers"/> array.
        /// You can test the value received against NCRYPTBUFFER_EMPTY (0) to determine whether the array pointed to by the <see cref="pBuffers"/> parameter contains any members.
        /// </summary>
        public int cBuffers;

        /// <summary>
        /// An array of <see cref="NCryptBuffer"/> structures that contain the buffer information. The <see cref="cBuffers"/> member contains the number of elements in this array.
        /// </summary>
        public NCryptBuffer* pBuffers;

        /// <summary>
        /// Creates an instance of the <see cref="NCryptBufferDesc"/> structure with
        /// the <see cref="ulVersion"/> field initialized to <see cref="NCRYPTBUFFER_VERSION"/>.
        /// </summary>
        /// <returns>The initialized instance of <see cref="NCryptBufferDesc"/>.</returns>
        public static NCryptBufferDesc Create() {
            return new NCryptBufferDesc {
                ulVersion = NCRYPTBUFFER_VERSION,
            };
        }
    }

    public unsafe partial struct NCryptBuffer {
        /// <summary>
        /// The size, in bytes, of the buffer.
        /// </summary>
        public int cbBuffer;

        /// <summary>
        /// A value that identifies the type of data that is contained by the buffer.
        /// </summary>
        public BufferType BufferType;

        /// <summary>
        /// The address of the buffer. The size of this buffer is contained in the <see cref="cbBuffer"/> member.
        /// The format and contents of this buffer are identified by the <see cref="BufferType"/> member.
        /// </summary>
        public void* pvBuffer;

        public NCryptBuffer(BufferType type, byte[] buffer) {
            fixed (void* ptr = &buffer[0]) {
                cbBuffer = buffer.Length;
                BufferType = type;
                pvBuffer = ptr;
            }
        }
    }



    public static class NgcInterop {

        [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
        public static extern unsafe SECURITY_STATUS NCryptKeyDerivation(SafeNCryptKeyHandle hKey, NCryptBufferDesc* pParameterList, byte[] pbDerivedKey, int cbDerivedKey, out int pcbResult,uint dwFlags);

        //[DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
        //public static extern SECURITY_STATUS NCryptDeriveKey(SafeNCryptKeyHandle derivationKey, NCryptBufferDesc paramList, byte[] derivedKey, uint derivedKeySize, out uint dervedKeyWritten, uint flags);


        [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
        public static extern SECURITY_STATUS NCryptImportKey(SafeNCryptProviderHandle provider, SafeNCryptKeyHandle importKey, string blobType, IntPtr paramList, out SafeNCryptKeyHandle outputKey, byte[] keyData, uint keyDataSize, uint importFlags);


        [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
        public static extern SECURITY_STATUS NCryptExportKey(SafeNCryptKeyHandle key, IntPtr exportKey, string blobType, IntPtr paramList, byte[] keyData, uint keyDataSize, out uint sizeWritten, uint importFlags);


        [DllImport("ncrypt.dll")]
        public static extern SECURITY_STATUS NCryptDecrypt(SafeNCryptKeyHandle hKey, [MarshalAs(UnmanagedType.LPArray)] byte[] pbInput, int cbInput, [MarshalAs(UnmanagedType.LPArray)] byte[] pPaddingInfo,
                                                            [MarshalAs(UnmanagedType.LPArray)] byte[] pbOutput, int cbOutput, out int pcbResult, NCryptEncryptFlags dwFlags);


        [DllImport("ncrypt.dll")]
        internal static extern SECURITY_STATUS NCryptEnumKeys(SafeNCryptProviderHandle hProvider,
                                                        [In, MarshalAs(UnmanagedType.LPWStr)] string pszScope,
                                                        [Out] out IntPtr ppKeyName,
                                                        [In, Out] ref IntPtr ppEnumState,
                                                        CngKeyOpenOptions dwFlags);

        [DllImport("ncrypt.dll")]
        internal static extern SECURITY_STATUS NCryptOpenStorageProvider([Out] out SafeNCryptProviderHandle phProvider,
                                                                          [MarshalAs(UnmanagedType.LPWStr)] string pszProviderName,
                                                                          int dwFlags);

        [DllImport("ncrypt.dll")]
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        [SuppressUnmanagedCodeSecurity]
        internal static extern SECURITY_STATUS NCryptFreeBuffer(IntPtr pvInput);

        [StructLayout(LayoutKind.Sequential)]
        public struct NCryptKeyName {
            [MarshalAs(UnmanagedType.LPWStr)]
            public string pszName;

            [MarshalAs(UnmanagedType.LPWStr)]
            public string pszAlgId;

            public int dwLegacyKeySpec;

            public int dwFlags;
        }


        public static string ReadNcgFileString(string path) {
            if (File.Exists(path)) {
                var fileData = File.ReadAllBytes(path);
                return Encoding.Unicode.GetString(fileData.Take(fileData.Length - 2).ToArray());
            }else {
                return null; 
            }
        }

        public static NCryptKeyName[] EnumerateKeys(this CngProvider provider, CngKeyOpenOptions openOptions) {

            SECURITY_STATUS status;

            if ((status = NCryptOpenStorageProvider(out SafeNCryptProviderHandle phProvider, provider.Provider, 0)) != SECURITY_STATUS.ERROR_SUCCESS) {
                throw new CryptographicException($"Failed top open provider {provider.Provider} with error {status}");
            }

            using (phProvider) {

                IntPtr enumState = IntPtr.Zero;
                RuntimeHelpers.PrepareConstrainedRegions();
                try {
                    List<NCryptKeyName> keys = new List<NCryptKeyName>();

                    status = SECURITY_STATUS.ERROR_SUCCESS;

                    // Loop over the NCryptEnumKeys until it tells us that there are no more keys to enumerate
                    do {
                        IntPtr algorithmBuffer;
                        status = NCryptEnumKeys(phProvider,
                                                    null,
                                                    out algorithmBuffer,
                                                    ref enumState,
                                                    openOptions);

                        if (status == SECURITY_STATUS.ERROR_SUCCESS) {
                            keys.Add(algorithmBuffer.ToStructure<NCryptKeyName>());
                            NCryptFreeBuffer(algorithmBuffer);
                        } else if (status != SECURITY_STATUS.NTE_NO_MORE_ITEMS) {
                            throw new CryptographicException((int)status);
                        }
                    }
                    while (status == SECURITY_STATUS.ERROR_SUCCESS);

                    return keys.ToArray();

                } finally {

                    if (enumState != IntPtr.Zero) {
                        NCryptFreeBuffer(enumState);
                    }
                }
            }
        }
    }
}
