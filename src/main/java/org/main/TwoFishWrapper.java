package org.example;


import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;

/**
 * TwoFishWrapper
 * Provides encryption and decryption funcionalities for TwoFish in EAX mode.
 */

public class TwoFishWrapper {
    Cipher cipher;

    public TwoFishWrapper() {
        try {
            Provider provider = new BouncyCastleFipsProvider();
            cipher = Cipher.getInstance("Twofish/EAX/NoPadding", provider);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    public byte[] encrypt(byte[] source, TwoFishEaxParameters params) {
        try {
            cipher.init(Cipher.ENCRYPT_MODE, params.keySpec, params.gcmSpec);
            return cipher.doFinal(source);

        } catch (InvalidAlgorithmParameterException | InvalidKeyException
                 | IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    public byte[] decrypt(byte[] source, TwoFishEaxParameters params) {
        try {
            cipher.init(Cipher.DECRYPT_MODE, params.keySpec, params.gcmSpec);
            return cipher.doFinal(source);

        } catch (InvalidAlgorithmParameterException | InvalidKeyException
                 | IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException(e);
        }
    }
}
