#pragma description kdbx file format
// This pattern file wouldn't have been possible without the blog post of Wladimir Palant
// Check it out here: https://palant.info/2023/03/29/documenting-keepass-kdbx4-file-format/#the-outer-header

#include <std/mem.pat>
#include <std/io.pat>
#include <type/guid.pat>
#include <type/magic.pat>

// kdbx files contain different signatures depending on the version they were created with
enum KeepassSignature : u32 {
    v1    = 0xB54BFB65,
    v2pre = 0xB54BFB66,
    v2    = 0xB54BFB67
};

enum Cipher : u128 {
    AES128_CBC = 0x61AB05A1946441C38D743A563DF8DD35,
    AES256_CBC = 0x31C1F2E6BF714350BE5805216AFC5AFF,
    CHACHA20   = 0xD6038A2B8B6F4CB5A524339A31DBB59A,
    SALSA20    = 0x716E1C8AEE174BDC93AEA977B882833A,
    SERPENT    = 0x098563FFDDF74F9886198079F6DB897A,
    TWOFISH    = 0xAD68F29F576F4BB9A36AD47AF965346C
};

// The available types for the header TLV entries
enum HeaderType : u8 {
  EndOfHeader         = 0x00,
  Comment             = 0x01,
  CipherID            = 0x02,
  CompressionFlags    = 0x03,
  MasterSeed          = 0x04,
  TransformSeed       = 0x05,
  TransformRounds     = 0x06,
  EncryptionIV        = 0x07,
  ProtectedStreamKey  = 0x08,
  StreamStartBytes    = 0x09,
  InnerRandomStreamID = 0x0A,
  KdfParameters       = 0x0B,
  PublicCustomData    = 0x0C
};

enum VariantMapEntryType : u8 {
    t_uint32  = 0x04,
    t_uint64  = 0x05,
    t_bool    = 0x08,
    t_int32   = 0x0C,
    t_string  = 0x18,
    t_bytearr = 0x42
};

// Entry in the VariantMap
struct VariantMapEntry {
    VariantMapEntryType type;
    
    // 0x00 indicates the end of the map
    if (type == 0x00) {
        break;
    }
    
    u32 keySize;
    char key[keySize];
    u32 valueSize;
    
    // We can use different data types depending on the type value
    match (type) {
        (VariantMapEntryType::t_uint32): u32 value;
        (VariantMapEntryType::t_uint64): u64 value;
        (VariantMapEntryType::t_bool): bool value;
        (VariantMapEntryType::t_int32): s32 value;
        (VariantMapEntryType::t_string): char value[valueSize];
        (VariantMapEntryType::t_bytearr): u8  value[valueSize];
        (_): u8 value[valueSize];
    }
    
    // The more reliable version would be to always parse an u8 array:
    // u8 value[valueSize];
} [[name(key)]];

// Structure for the KdfParameters and PublicCustomData header fields
struct VariantMap {
    u16 formatVersion;
    VariantMapEntry entries[while(std::mem::read_unsigned($, 1) != 0x00)];
    u8 endOfMap;
};

// The kdbx header consists of multiple Type-Length-Value entries
struct TLV_Entry {
    HeaderType headerType [[color("80ff00")]];

    // Length has different size depending on kdbx version
    match (parent.kdbxVersionMajor) {
        (3): u16 length [[color("0080ff")]];
        (4): u32 length [[color("0080ff")]];
        (_): return;
    }

    match (headerType) {
      (HeaderType::KdfParameters): VariantMap kdfParams;
      (HeaderType::PublicCustomData): VariantMap publicCustomData;
      (HeaderType::CompressionFlags): u32 compression;
      (HeaderType::CipherID): be type::GUID uuid;
      (_): u8 value[length] [[color("00bfff")]];
    }
    
    // Add extra check for EndOfHeader so that value gets parsed properly
    if (headerType == HeaderType::EndOfHeader) {
        break;
    }
} [[name(headerType)]];

// Find the offset of the end of the header
u32 EndOfHeaderOffset = std::mem::find_sequence(0, 0x0d, 0x0a, 0x0d, 0x0a);

struct Header {
    // All kdbx files share a common set of magic bytes @ 0x00
    type::Magic<"\x03\xD9\xA2\x9A"> magicBytes;
    KeepassSignature keepassSignature;
    
    u16 kdbxVersionMinor;
    u16 kdbxVersionMajor;
    
    std::print("Parsing KDBX version {}.{}", kdbxVersionMajor, kdbxVersionMinor);
    
    // Dynamically parse all the TLV entries of the header until the EndOfHeader entry was found
    TLV_Entry HeaderFields[while($ < EndOfHeaderOffset)];
    
    // The signature fields are were introduced with kdbx version 4
    if (kdbxVersionMajor >= 4) {
        u32 headerSHA256;
        u32 headerHMAC_SHA256;
    }
};

Header header @ 0x00;

// After the header follows the encrypted keepass data
u8 encryptedData[while(!std::mem::eof())] @ $ [[color("2ca02c")]];