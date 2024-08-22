# PktDecryptor
An easy way to peek inside PacketTracer Files!
## Why bother?
Want to make an app that uses network configurations? Well, it would be cool if the user could use Cisco PacketTracer to build them. But it's not that easy - Cisco decided that, for some unknown reason, the save files would be encrypted. And not just obfuscated in a simple way - I mean, *seriously encrypted*.

Thanks to the brilliant work by [ferib](https://github.com/ferib) and [mircodz](https://github.com/mircodz) who managed to reverse-engineer the encryption, we can now finally access the data. However, I had huge issues compiling mircodz's C library on Windows (I am not that experienced yet), therefore I decided it would be easier to rewrite it in Java.

## Usage

`java -jar out/artifacts/PktDecryptor_jar/PktDecryptor.jar -d src/test/test.pkt src/test/result.xml`

## The encryption process
### PacketTracer Version 7 and above
The encryption has 4 stages:

 1. **Compression using zlib**. Default compression level. The length of the input XML is added to the compressed blob as a 4-byte unsigned number at the beginning, so the output of this stage is | XML_length_4_bytes | compressed_blob |.
 2. **Obfuscation** using the formula `output[i] = input[i] ^ (INPUT_LENGTH ^ i)`
 3. **Encryption using TwoFish** in [EAX mode](https://en.wikipedia.org/wiki/EAX_mode). For .pkt files, the following parameters are used:
	 - Key: `0x89` repeated 16 times
	 - Initialization vector: `0x10` repeated 16 times 
	 - MAC length: 16 bytes
 4. **Obfuscation** using the formula `output[INPUT_LENGTH + ~i] = input[i] ^ (INPUT_LENGTH - i * INPUT_LENGTH)`

### PacketTracer Version 5-6
Work still in progress
### PacketTracer Version 4 and below
Work still in progress

