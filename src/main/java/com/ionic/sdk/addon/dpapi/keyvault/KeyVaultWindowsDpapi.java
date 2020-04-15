package com.ionic.sdk.addon.dpapi.keyvault;

import com.ionic.sdk.addon.dpapi.cipher.DpapiCipher;
import com.ionic.sdk.cipher.CipherAbstract;
import com.ionic.sdk.core.value.Value;
import com.ionic.sdk.core.vm.VM;
import com.ionic.sdk.error.IonicException;
import com.ionic.sdk.error.SdkError;
import com.ionic.sdk.keyvault.KeyVaultBase;
import com.ionic.sdk.keyvault.KeyVaultEncryptedFile;
import com.ionic.sdk.keyvault.KeyVaultFileModTracker;
import com.ionic.sdk.keyvault.KeyVaultKeyRecord;

import java.io.File;
import java.util.Map;
import java.util.logging.Logger;

/**
 * Platform specific Encrypted Key Vault for Windows - using DP API.
 */
public final class KeyVaultWindowsDpapi extends KeyVaultBase {

    /**
     * Private const for security level of DPAPI.
     */
    private static final int DPAPI_VAULT_SECURITY_LEVEL = 100;

    /**
     * Private const for DPAPI ID.
     */
    private static final String DPAPI_VAULT_ID = "dpapi";

    /**
     * Private const for DPAPI Label.
     */
    private static final String DPAPI_VAULT_LABEL = "Windows DPAPI Key Vault";

    /**
     * The folder, relative to USER PROFILE DIR, in which default Ionic files are stored.
     */
    private static final String KEYVAULT_USER_FOLDER_IONIC = "AppData/LocalLow/IonicSecurity/KeyVaults";

    /**
     * The name of the file in USER_FOLDER_IONIC, in which the default Ionic Key Vault is stored.
     */
    private static final String DEFAULT_KEYVAULT_FILENAME = "KeyVaultDpapi.dat";

    /**
     * The cipher used to encrypt and decrypt the key vault file.
     */
    private final CipherAbstract cipher;

    /**
     * The user-specified filesystem path to which the KeyVault file should be saved.  If null, use
     * the default location.
     */
    private String overrideFilePath;

    /**
     * File modification tracker lets us know if the file has been updated since the last time we accessed it.
     */
    private KeyVaultFileModTracker fileModTracker = null;

    /**
     * Class scoped logger.
     */
    private final Logger logger = Logger.getLogger(getClass().getName());

    /**
     * Get the filesystem path used for persistence of the serialized form of this KeyVault instance.
     * <p>
     * For the DPAPI (Windows Platform) KeyVault implementation, a default path is used when left unspecified by
     * the user:
     * <ul><li>'[UserHome]\AppData\LocalLow\IonicSecurity\KeyVaults\KeyVaultDpapi.dat'</li></ul>
     *
     * @return the filesystem path used for persistence of the serialized form of this KeyVault instance
     */
    private String getDefaultFilePath() {
        // determine IonicSecurity folder path
        final File folderUserHome = new File(System.getProperty(VM.Sys.USER_HOME));

        // determine KeyVaults folder path
        final File folderIonic = new File(folderUserHome, KEYVAULT_USER_FOLDER_IONIC);
        final File fileIonic = new File(folderIonic, DEFAULT_KEYVAULT_FILENAME);
        return fileIonic.getPath();
    }

    /**
     * default constructor.
     *
     * @throws IonicException on failure of the underlying JRE cipher to initialize
     */
    public KeyVaultWindowsDpapi() throws IonicException {
        super();
        this.cipher = new DpapiCipher(null, true);
        this.overrideFilePath = null;
    }

    /**
     * Constructor with specific filename.
     *
     * @param filePath File path to store the encrypted key vault.
     * @throws IonicException on failure of the underlying JRE cipher to initialize
     */
    public KeyVaultWindowsDpapi(final String filePath) throws IonicException {
        super();
        this.cipher = new DpapiCipher(null, true);
        this.overrideFilePath = filePath;
    }

    /**
     * ID accessor.
     * @return Vault ID constant
     */
    @Override
    public String getId() {
        return DPAPI_VAULT_ID;
    }

    /**
     * Label accessor.
     * @return Vault label constant
     */
    @Override
    public String getLabel() {
        return DPAPI_VAULT_LABEL;
    }

    /**
     * Return the security level of this class.
     * @return 100 (constant)
     */
    @Override
    public int getSecurityLevel() {
        return DPAPI_VAULT_SECURITY_LEVEL;
    }

    /**
     * Get the file path used for key vault data storage.
     * @return Returns the file path used for key vault data storage.
     *         If a file path has not yet been set into the key vault, then the default
     *         file path will be returned.
     */
    private String getFilePathInternal() {
        return (Value.isEmpty(overrideFilePath) ? getDefaultFilePath() : overrideFilePath);
    }

    /**
     * Get the file path used for key vault data storage.
     * @return Returns the file path used for key vault data storage.
     *         If a file path has not yet been set into the key vault, then the default
     *         file path will be returned.
     */
    @SuppressWarnings({"checkstyle:testPublicShouldNotCallPublic"})
    public String getFilePath() {
        return getFilePathInternal();
    }

    /**
     * Set the file path used for key vault data storage.
     * Sets the file path used for key vault data storage. If no file path
     * is ever set, or if it is set to empty string, then the default file path
     * will be used.
     * @param filePath The file path to use for key vault data storage.
     */
    public void setFilePath(final String filePath) {
        overrideFilePath = filePath;
    }

    /**
     * Clears the internal storage.
     */
    @Override
    public void cleanVaultStore() {
        logger.fine("cleanVaultStore()");

        mapKeyRecords.clear();
        try {
            final String filePath = getFilePathInternal();
            final File outputFile = new File(filePath);
            if (!outputFile.delete()) {
                logger.info("Failed to delete the vault store file - may not exist yet.");
            }
        } catch (Exception e) {
            logger.severe(String.format("Exception attempting to delete the vault store file: %s.", e.toString()));
        }
    }

    /**
     * Function takes a map of key records and should move them from encrypted file persistent storage
     * into this map.
     * @return mapKeyRecordsOut map of key id to key records where saved records should be stored
     * @throws IonicException If the load runs into IO errors.
     */
    @Override
    protected Map<String, KeyVaultKeyRecord> loadAllKeyRecords() throws IonicException {
        logger.fine("loadAllKeyRecords()");

        // check to see if the input file exists
        final String filePath = getFilePathInternal();
        final File inputCipherFile = new File(filePath);

        if (!inputCipherFile.exists()) {
            throw new IonicException(SdkError.ISKEYVAULT_RESOURCE_NOT_FOUND,
                                     String.format("No key vault storage file exists at '%s'.",
                                                  inputCipherFile.getAbsolutePath()));
        }

        // record file information. if the file has not changed since our last
        // load or save operation, then we can skip this load operation
        if (fileModificationPoint(filePath) == KeyVaultFileModTracker.Result.FILE_UNCHANGED) {
            throw new IonicException(SdkError.ISKEYVAULT_LOAD_NOT_NEEDED,
                                     "File has not changed since last load.");
        }

        // read encrypted file.
        final KeyVaultEncryptedFile file = new KeyVaultEncryptedFile(DPAPI_VAULT_ID);
        return file.loadAllKeyRecordsFromFile(inputCipherFile.getAbsolutePath(), cipher);
    }

    /**
     * Function takes a map of key records and should move them into encrypted file persistent storage.
     * @param  mapKeyRecords map of key id to key records that should be saved
     * @return ISKEYVAULT_OK on success, or some other non-zero error code.
     * @throws IonicException If the load runs into I/O errors.
     */
    @Override
    protected int saveAllKeyRecords(final Map<String, KeyVaultKeyRecord> mapKeyRecords) throws IonicException {
        logger.fine("saveAllKeyRecords()");

        // write encrypted file
        final String filePath = getFilePathInternal();
        final KeyVaultEncryptedFile file = new KeyVaultEncryptedFile(DPAPI_VAULT_ID);
        file.saveAllKeyRecordsToFile(cipher, mapKeyRecords, filePath);

        // record file information
        fileModificationPoint(filePath);

        return SdkError.ISKEYVAULT_OK;
    }

    /**
     * Function that uses the KeyVaultFileModTracker to determine whether the key vault has changed
     * outside the context of this instance of the vault.
     *
     * @param filePath the filesystem path associated with the KeyVault file
     * @return A {@link KeyVaultFileModTracker.Result}
     */
    private KeyVaultFileModTracker.Result fileModificationPoint(final String filePath) {
        // if we don't have a file tracker object, or we have changed the file we are tracking, then
        // create a new one here
        if ((fileModTracker == null) || !fileModTracker.getFilePath().equals(filePath)) {

            fileModTracker = new KeyVaultFileModTracker(filePath);
        }

        return fileModTracker.recordFileInfo();
    }
}
