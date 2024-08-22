package org.example;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.HexFormat;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

/**
 * PktTransformer
 * Decrypts and encrypts PacketTracer network save files into XML
 * Based on research by (<a href="https://github.com/mircodz/pka2xml">mircodz</a>)
 *
 * Works for PacketTracer version 7+
 */

public class PktTransformer {
    private static void hexdump(byte[] data) {
        HexFormat hex = HexFormat.ofDelimiter(" ");
        System.out.print(hex.formatHex(data, 0, 8));
        System.out.print("  ...  ");
        System.out.print(hex.formatHex(data, data.length - 8, data.length));
        System.out.printf("   l=%d\n", data.length);
    }

    private static void chardump(byte[] data) {
        System.out.println(new String(data, 0, 64));
        System.out.println("  ...  ");
        System.out.println(new String(data, data.length - 64, 64));
    }

    /**
     * Decryption - Stage 1
     * The data is deobfuscated using the following formula:
     * out[i] = in[input_length + ~i] ^ (input_length - i * input_length)
     *
     * @param input input byte array
     * @return processed byte array
     */
    private static byte[] decryptStageOne(byte[] input) {
        int l = input.length;
        byte[] output = new byte[l];

        for (int i = 0; i < l; i++) {
            output[i] = (byte) (input[l + ~i] ^ (l - i * l));
        }

        return output;
    }

    /**
     * Decryption - Stage 2
     * The data is decrypted using TwoFish block algorithm in EAX mode.
     * MAC size is 16 bytes.
     * No padding is required in EAX.
     * For .pkt files, the key using 16 repeating 0x89 bytes and IV using 16 repeating 0x10 bytes is used.
     *
     * In previous PacketTracer versions the encryption used a CBC chaining mode with PKCS#5 padding
     *
     * @param input input byte array
     * @return processed byte array
     */
    private static byte[] decryptStageTwo(byte[] input) {
        TwoFishWrapper fish = new TwoFishWrapper();
        TwoFishEaxParameters params = new TwoFishEaxParameters("89", "10");

        return fish.decrypt(input, params);
    }

    /**
     * Decryption - Stage 3
     * Again, the data is deobfuscated using a formula
     * out[i] = in[i] ^ (input_length - i)
     *
     * @param input input byte array
     * @return processed byte array
     */
    private static byte[] decryptStageThree(byte[] input) {
        int l = input.length;
        byte[] output = new byte[l];

        for (int i = 0; i < l; i++) {
            output[i] = (byte) (input[i] ^ (l - i));
        }

        return output;
    }

    /**
     * Decryption - Stage 4
     * The data is decompressed using zlib.
     * The first four bytes correspond to the length of the result.
     * Therefore they are omitted during the decompression.
     *
     * @param input input byte array
     * @return processed byte array
     */
    private static byte[] decryptStageFour(byte[] input) {
        int outputLength = (
                ((input[0] & 0xFF) << 24)
                | ((input[1] & 0xFF) << 16)
                | ((input[2] & 0xFF) << 8)
                | (input[3] & 0xFF));

        byte[] output = new byte[outputLength];
        Inflater inflater = new Inflater();
        inflater.setInput(input, 4, input.length - 4);

        try {
            inflater.inflate(output);
            assert inflater.finished();

        } catch (DataFormatException e) {
            throw new RuntimeException(e);
        }

        return output;
    }

    /**
     * Encryption stage 1 - compression
     * See decryptStageFour() - it's the same but in reverse
     * @param input input byte array
     * @return processed byte array
     */
    private static byte[] encryptStageOne(byte[] input) {
        int outputBufferLength = input.length + input.length / 100 + 17;

        byte[] output = new byte[outputBufferLength];
        output[0] = (byte) ((input.length & 0xFF000000) >> 24);
        output[1] = (byte) ((input.length & 0x00FF0000) >> 16);
        output[2] = (byte) ((input.length & 0x0000FF00) >> 8);
        output[3] = (byte) (input.length & 0x000000FF);

        Deflater deflater = new Deflater();
        deflater.setLevel(-1);
        deflater.setInput(input);
        deflater.finish();
        int outputLength = deflater.deflate(output, 4, outputBufferLength - 4);
        assert deflater.finished();

        // Need to truncate the buffer so that the excessive \0s don't get taken into crypto functions
        byte[] shortOutput = new byte[outputLength];
        System.arraycopy(output, 0, shortOutput, 0, outputLength);
        return shortOutput;
    }

    /**
     * Encryption stage 2 - obfuscation
     * See decryptStageThree() - it's the same but in reverse
     * @param input input byte array
     * @return processed byte array
     */
    private static byte[] encryptStageTwo(byte[] input) {
        byte[] output = new byte[input.length];
        for (int i = 0; i < input.length; i++) {
            output[i] = (byte) (input[i] ^ (input.length - i));
        }
        return output;
    }

    /**
     * Encryption stage 3 - TwoFish encryption
     * See decryptStageTwo() - it's the same but in reverse
     * @param input input byte array
     * @return processed byte array
     */
    private static byte[] encryptStageThree(byte[] input) {
        TwoFishWrapper fish = new TwoFishWrapper();
        TwoFishEaxParameters params = new TwoFishEaxParameters("89", "10");

        return fish.encrypt(input, params);
    }

    /**
     * Encryption stage 4 - obfuscation
     * See decryptStageOne() - it's the same but in reverse
     * @param input input byte array
     * @return processed byte array
     */
    private static byte[] encryptStageFour(byte[] input) {
        int l = input.length;
        byte[] output = new byte[l];
        for (int i = 0; i < l; i++) {
            output[l + ~i] = (byte) (input[i] ^ (l - i * l));
        }
        return output;
    }


    public static void encrypt(String inputPath, String outputPath) {
        encrypt(inputPath, outputPath, false);
    }

    /**
     * Encrypts a PacketTracer file in XML format to PKT format.
     * @param inputPath Path to XML
     * @param outputPath Path to PKT output
     * @param verbose Hexdump bytes from all stages
     */
    public static void encrypt(String inputPath, String outputPath, boolean verbose) {
        try {
            byte[] data = Files.readAllBytes(Paths.get(inputPath));
            if (verbose) {
                System.out.printf("\nEncrypting file:  %s\n", inputPath);
                System.out.print("Initial | ");
                hexdump(data);
                System.out.print("Stage 1 | ");
            }
            data = encryptStageOne(data);

            if (verbose) {
                hexdump(data);
                System.out.print("Stage 2 | ");
            }
            data = encryptStageTwo(data);

            if (verbose) {
                hexdump(data);
                System.out.print("Stage 3 | ");
            }
            data = encryptStageThree(data);

            if (verbose) {
                hexdump(data);
                System.out.print("Stage 4 | ");
            }
            data = encryptStageFour(data);

            if (verbose) {
                hexdump(data);
            }

            Files.write(Paths.get(outputPath), data, StandardOpenOption.CREATE);
        }
        catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static void decrypt(String inputPath, String outputPath) {
        PktTransformer.decrypt(inputPath, outputPath, false);
    }

    /**
     * Decrypts a PacketTracer file from PKT format to XML.
     * @param inputPath Path to PKT
     * @param outputPath Path to XML output
     * @param verbose Hexdump bytes from all stages
     */
    public static void decrypt(String inputPath, String outputPath, boolean verbose) {
        try {
            byte[] data = Files.readAllBytes(Paths.get(inputPath));
            if (verbose) {
                System.out.printf("\nDecrypting file:  %s\n", inputPath);
                System.out.print("Initial | ");
                hexdump(data);
                System.out.print("Stage 1 | ");
            }
            data = decryptStageOne(data);

            if (verbose) {
                hexdump(data);
                System.out.print("Stage 2 | ");
            }
            data = decryptStageTwo(data);

            if (verbose) {
                hexdump(data);
                System.out.print("Stage 3 | ");
            }
            data = decryptStageThree(data);

            if (verbose) {
                hexdump(data);
                System.out.print("Stage 4 | ");
            }
            data = decryptStageFour(data);

            if (verbose) {
                hexdump(data);
                chardump(data);
            }

            Files.write(Paths.get(outputPath), data, StandardOpenOption.CREATE);
        }
        catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
