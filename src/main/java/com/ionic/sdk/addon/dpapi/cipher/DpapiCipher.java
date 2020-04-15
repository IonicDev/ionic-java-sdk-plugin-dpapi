package com.ionic.sdk.addon.dpapi.cipher;

import com.github.windpapi4j.InitializationFailedException;
import com.github.windpapi4j.WinAPICallFailedException;
import com.github.windpapi4j.WinDPAPI;
import com.ionic.sdk.cipher.CipherAbstract;
import com.ionic.sdk.core.codec.Transcoder;
import com.ionic.sdk.core.value.Value;
import com.ionic.sdk.error.IonicException;
import com.ionic.sdk.error.SdkData;
import com.ionic.sdk.error.SdkError;

import java.util.logging.Logger;

/**
 * Windows Data Protection API implementation.
 * <p>
 * The Data Protection API (DPAPI) is a service that is provided by the Windows operating system. It provides
 * protection using the user or machine credentials to encrypt or decrypt data.
 * <p>
 * When the machine key is used to encrypt data, decryption is only possible on the same machine.  When the user
 * profile key is used to encrypt data, decryption is only possible in the context of the same user profile.
 */
public final class DpapiCipher extends CipherAbstract {

    /**
     * Class scoped logger.
     */
    private static final Logger LOGGER = Logger.getLogger(DpapiCipher.class.getName());

    /**
     * The library object providing access to DPAPI.
     */
    private final WinDPAPI winDPAPI;

    /**
     * Additional data used by DPAPI to secure content.
     */
    private final String entropy;

    /**
     * ID for AesGcmCipher class cipher.
     */
    private static final String ID = "dpapi";
    /**
     * Label for AesGcmCipher class cipher.
     */
    private static final String LABEL = "DP API Cipher";

    /**
     * Constructor.  The DPAPI user profile key will be used for encryption operations.
     *
     * @param entropy additional state (can be from the machine) used to secure the data
     * @throws IonicException on use when on non-Windows OS
     */
    public DpapiCipher(final String entropy) throws IonicException {
        this(entropy, true);
    }

    /**
     * Constructor.
     *
     * @param entropy additional state (can be from the machine) used to secure the data
     * @param isUser  true if DPAPI user profile key is to be used; false if the DPAPI machine key is to be used
     * @throws IonicException on use when on non-Windows OS
     */
    public DpapiCipher(final String entropy, final boolean isUser) throws IonicException {
        super(null);
        this.winDPAPI = getInstanceDPAPI(isUser);
        this.entropy = entropy;
    }

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public String getLabel() {
        return LABEL;
    }

    /**
     * Encrypt a byte array and return the result as another byte array.
     *
     * @param plainText array of bytes to encrypt
     * @return array of bytes representing the ciphertext
     * @throws IonicException on cryptography errors
     */
    @Override
    public byte[] encrypt(final byte[] plainText) throws IonicException {
        SdkData.checkTrue(!Value.isEmpty(plainText), SdkError.ISCRYPTO_NULL_INPUT, null);
        return protectData(winDPAPI, plainText, entropy);
    }

    /**
     * Encrypt a string and return the result as a byte array.
     *
     * @param plainText Plaintext String to encrypt.
     * @return An array of bytes representing the ciphertext.
     * @throws IonicException on cryptography errors
     */
    @Override
    public byte[] encrypt(final String plainText) throws IonicException {
        SdkData.checkTrue(!Value.isEmpty(plainText), SdkError.ISCRYPTO_NULL_INPUT, null);
        return protectData(winDPAPI, Transcoder.utf8().decode(plainText), entropy);
    }

    /**
     * Decrypt a previously encrypted byte array and return the result as another byte array.
     *
     * @param cipherText array of bytes to decrypt
     * @return array of bytes representing the decrypted plaintext
     * @throws IonicException on cryptography errors
     */
    @Override
    public byte[] decrypt(final byte[] cipherText) throws IonicException {
        SdkData.checkTrue(!Value.isEmpty(cipherText), SdkError.ISCRYPTO_NULL_INPUT, null);
        return unprotectData(winDPAPI, cipherText, entropy);
    }

    /**
     * Retrieve the library object used to access the DPAPI function.
     *
     * @param isUser true if DPAPI user profile key is to be used; otherwise, the DPAPI machine key will be used
     * @return an object reference which exposes the DPAPI functionality
     * @throws IonicException on failure to acquire the reference
     */
    private static WinDPAPI getInstanceDPAPI(final boolean isUser) throws IonicException {
        try {
            return isUser
                    ? WinDPAPI.newInstance(WinDPAPI.CryptProtectFlag.CRYPTPROTECT_UI_FORBIDDEN)
                    : WinDPAPI.newInstance(WinDPAPI.CryptProtectFlag.CRYPTPROTECT_UI_FORBIDDEN,
                    WinDPAPI.CryptProtectFlag.CRYPTPROTECT_LOCAL_MACHINE);
        } catch (InitializationFailedException e) {
            LOGGER.severe(String.format("Exception attempting WinDPAPI newInstance: %s.", e.toString()));
            throw new IonicException(SdkError.ISAGENT_RESOURCE_NOT_FOUND, e);
        }
    }

    /**
     * Invoke the "protect" API to encrypt some platform-protected data.
     *
     * @param winDPAPI         the object reference which exposes the DPAPI functionality
     * @param bytesUnprotected the unprotected bytes
     * @param entropy          additional state (can be from the machine) used to secure the data
     * @return the protected bytes
     * @throws IonicException on cryptography errors
     */
    private static byte[] protectData(final WinDPAPI winDPAPI,
                                      final byte[] bytesUnprotected,
                                      final String entropy) throws IonicException {
        try {
            return Value.isEmpty(entropy)
                    ? winDPAPI.protectData(bytesUnprotected)
                    : winDPAPI.protectData(bytesUnprotected, Transcoder.utf8().decode(entropy));
        } catch (WinAPICallFailedException e) {
            LOGGER.severe(String.format("Exception attempting WinDPAPI protectData: %s.", e.toString()));
            throw new IonicException(SdkError.ISAGENT_RESOURCE_NOT_FOUND, e);
        }
    }

    /**
     * Invoke the "unprotect" API to decrypt some platform-protected data.
     *
     * @param winDPAPI       the object reference which exposes the DPAPI functionality
     * @param bytesProtected the protected bytes
     * @param entropy        additional state (can be from the machine) used to secure the data
     * @return the unprotected bytes
     * @throws IonicException on cryptography errors
     */
    private static byte[] unprotectData(final WinDPAPI winDPAPI,
                                        final byte[] bytesProtected,
                                        final String entropy) throws IonicException {
        try {
            return Value.isEmpty(entropy)
                    ? winDPAPI.unprotectData(bytesProtected)
                    : winDPAPI.unprotectData(bytesProtected, Transcoder.utf8().decode(entropy));
        } catch (WinAPICallFailedException e) {
            LOGGER.severe(String.format("Exception attempting WinDPAPI unprotectData: %s.", e.toString()));
            throw new IonicException(SdkError.ISAGENT_RESOURCE_NOT_FOUND, e);
        }
    }
}
