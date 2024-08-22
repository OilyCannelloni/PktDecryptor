package org.example;

import org.bouncycastle.util.encoders.Hex;

import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * TwoFishEaxParameters
 * Running Twofish in EAX mode requires three parameters:
 * - a 16-byte key. In this usage, the keys are always made of same byte repeated 16 times.
 * - an Initialization Vector, same as the key
 * - MAC length in bits, constant = 16 * 8 bits
 */

public class TwoFishEaxParameters {
    public final SecretKeySpec keySpec;
    public final GCMParameterSpec gcmSpec;

    public TwoFishEaxParameters(String key, String iv) {
        if (key.length() == 2) key = new String(new char[16]).replace("\0", key);
        if (iv.length() == 2) iv = new String(new char[16]).replace("\0", iv);
        byte[] hexKey = Hex.decode(key);
        byte[] hexIv = Hex.decode(iv);
        assert hexKey.length == 16 && hexIv.length == 16;
        keySpec = new SecretKeySpec(hexKey, "Twofish");
        gcmSpec = new GCMParameterSpec(16 * 8, hexIv);
    }
}
