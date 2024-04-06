# KeePass binary file parser

This tool is a parser for the KeePass binary file format.
It helps you understand the structure of the file and extract information from it, such as the used encryption algorithm, information about the key derivation function, and the length of encrypted data.

I also created a hexpat pattern for the [imhex](https://github.com/WerWolv/ImHex) hex editor. Check it out at [docs/kdbx.hexpat](https://github.com/d-Rickyy-b/kdbxParser/tree/master/docs/kdbx.hexpat).

## Example

```
> .\kdbxParser.exe -f test.kdbx        
MagicBytes:     0x9AA2D903
Signature:      v2
Version:        3.1
Headers:
        Cipher:         AES256_CBC
        CompressionFlags:       0x1
        MasterSeed:     0xD14BB45C5B695766054516A975FE4EACB5B6702A786F8454C1786E7681913860
        TransformSeed:  0x7D846DA87AADA5D63BD5A370EEA63B88B748CC3801E38AE20B58B36CACDC5AF2
        TransformRounds:        60000
        EncryptionIV:   0x&CB516A172D99A24FE83B78241F99DFA9
        StreamKey:      0x814F75A0C2CA9AC8F145CFBCBE7AB18C9C52F6998E51D0EEF487E18BB4D22D7B
        StreamStartBytes:       0x2CA297A93128393D1F5C447C4A35A6666DA925EC2E797F4FA2203EFE4908598F
        RandomStreamID: 2

HeaderSHA256:           0x0
HeaderHMACSHA256:       0x0
EncryptedData:          1744 bytes
```

## Usage

```text
usage: kdbxParser [-h|--help] -f|--file "<value>" [--json] [-p|--pretty] [-t|--template "<value>"]
                  Obtain metadata from a KeePass file

Arguments:

  -h  --help      Print help information
  -f  --file      Path to the keepass file
      --json      Print the result as a json string. Default: false
  -p  --pretty    Prettify the json output. Default: false
  -t  --template  Go template to format the output with - e.g. {{.Version}}. Default:
```

## Build from source

Building from source is easy:

```bash
go build ./cmd/kdbxParser
```

It wouldn't have been possible without [this article](https://palant.info/2023/03/29/documenting-keepass-kdbx4-file-format/) by Wladimir Palant, [this GitHub Gist](https://gist.github.com/lgg/e6ccc6e212d18dd2ecd8a8c116fb1e45), and last but not least, the [KeePass docs](https://keepass.info/help/kb/kdbx_4.html).
