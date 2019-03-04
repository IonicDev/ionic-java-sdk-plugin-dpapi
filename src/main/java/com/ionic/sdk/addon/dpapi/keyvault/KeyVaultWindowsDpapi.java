package com.ionic.sdk.addon.dpapi.keyvault;

import com.ionic.sdk.addon.dpapi.cipher.DpapiCipher;
import com.ionic.sdk.core.vm.VM;
import com.ionic.sdk.error.SdkError;
import com.ionic.sdk.error.IonicException;
import com.ionic.sdk.keyvault.KeyVaultBase;
import com.ionic.sdk.keyvault.KeyVaultEncryptedFile;
import com.ionic.sdk.keyvault.KeyVaultFileModTracker;
import com.ionic.sdk.keyvault.KeyVaultKeyRecord;

import java.io.File;
import java.util.logging.Logger;
import java.util.Map;

/**
 * Platform specific Encrypted Key Vault for Windows - using DP API.
 */
public class KeyVaultWindowsDpapi extends KeyVaultBase {

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
     * Filepath to save the DPAPI file, if null, use the default location.
     */
    private String overrideFilePath = null;

    /**
     * File modification tracker lets us know if the file has been updated since the last time we accessed it.
     */
    private KeyVaultFileModTracker fileModTracker = null;

    /**
     * Class scoped logger.
     */
    private final Logger logger = Logger.getLogger(getClass().getName());

    /**
     * Get the default folder for Key Vault files on the Windows Platform.
     * '[UserHome]\AppData\LocalLow\IonicSecurity\KeyVaults'
     * @return default file path
     */
    private static String getDefaultKeyVaultFolderPath() {
        // determine IonicSecurity folder path
        final File folderUserHome = new File(System.getProperty(VM.Sys.USER_HOME));

        // determine KeyVaults folder path
        final File folderIonic = new File(folderUserHome, KEYVAULT_USER_FOLDER_IONIC);

        return folderIonic.getAbsolutePath();
    }

    /**
     * default constructor.
     */
    public KeyVaultWindowsDpapi() {
        super();
    }

    /**
     * Constructor with specific filename.
     * @param filePath File path to store the encrypted key vault.
     */
    public KeyVaultWindowsDpapi(final String filePath) {
        super();
        overrideFilePath = filePath;
    }

    /**
     * ID accessor.
     * @return Vault ID constant
     */
    @Override
    public final String getId() {
        return DPAPI_VAULT_ID;
    }

    /**
     * Label accessor.
     * @return Vault label constant
     */
    @Override
    public final String getLabel() {
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
     * Annoying private duplicate function because of the PublicShouldNotCallPublic rule.
     * @return returns a default path, see the public version getDefaultFilePath()
     */
    private String internalGetDefaultFilePath() {

        File ionicPath = new File(getDefaultKeyVaultFolderPath());
        File ionicFile = new File(ionicPath, DEFAULT_KEYVAULT_FILENAME);
        return ionicFile.getAbsolutePath();
    }

    /**
     * Get the default file path used for key vault data storage.
     * @return Returns the default file path used for key vault data storage, which is
     *         '[UserHome]\AppData\LocalLow\IonicSecurity\KeyVaults\KeyVaultDpapi.dat'.
     *         This file path will be used unless otherwise specified by ISKeyVaultWindowsDpapi::setFilePath().
     */
    @SuppressWarnings({"checkstyle:testPublicShouldNotCallPublic"})
    public String getDefaultFilePath() {

        return internalGetDefaultFilePath();
    }

    /**
     * Annoying private duplicate function because of the PublicShouldNotCallPublic rule.
     * @return returns the current path, see the public version getFilePath()
     */
    private String internalGetFilePath() {

        // if an override path has not been set yet, then return the default file path
        if (overrideFilePath == null || overrideFilePath.length() == 0) {
            return internalGetDefaultFilePath();
        } else {
            return overrideFilePath;
        }
    }

    /**
     * Get the file path used for key vault data storage.
     * @return Returns the file path used for key vault data storage.
     *         If a file path has not yet been set into the key vault, then the default
     *         file path will be returned (ISKeyVaultWindowsDpapi::getDefaultFilePath()).
     */
    @SuppressWarnings({"checkstyle:testPublicShouldNotCallPublic"})
    public String getFilePath() {

        return internalGetFilePath();
    }

    /**
     * Set the file path used for key vault data storage.
     * Sets the file path used for key vault data storage. If no file path
     * is ever set, or if it is set to empty string, then the default file path
     * will be used (ISKeyVaultWindowsDpapi::getDefaultFilePath()).
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
        mapKeyRecords.clear();
        try {
            File outputFile = new File(internalGetFilePath());
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
     * @return mapKeyRecordsOut std::map of key id to key records where saved records should be stored
     * @throws IonicException If the load runs into IO errors.
     */
    @Override
    protected Map<String, KeyVaultKeyRecord> loadAllKeyRecords() throws IonicException {

        // check to see if the input file exists
        final File inputCipherFile = new File(internalGetFilePath());

        if (!inputCipherFile.exists()) {
            throw new IonicException(SdkError.ISKEYVAULT_RESOURCE_NOT_FOUND,
                                     String.format("No key vault storage file exists at '%s'.",
                                                  inputCipherFile.getAbsolutePath()));
        }

        // record file information. if the file has not changed since our last
        // load or save operation, then we can skip this load operation
        if (fileModificationPoint() == KeyVaultFileModTracker.Result.FILE_UNCHANGED) {
            throw new IonicException(SdkError.ISKEYVAULT_LOAD_NOT_NEEDED,
                                     "File has not changed since last load.");
        }

        // read encrypted file.
        DpapiCipher cipher = new DpapiCipher(null);
        KeyVaultEncryptedFile file = new KeyVaultEncryptedFile(DPAPI_VAULT_ID);
        return file.loadAllKeyRecordsFromFile(inputCipherFile.getAbsolutePath(), cipher);
    }

    /**
     * Function takes a map of key records and should move them into encrypted file persistent storage.
     * @param  mapKeyRecords std::map of key id to key records that should be saved
     * @return ISKEYVAULT_OK on success, or some other non-zero error code.
     * @throws IonicException If the load runs into IO errors.
     */
    @Override
    protected int saveAllKeyRecords(final Map<String, KeyVaultKeyRecord> mapKeyRecords) throws IonicException {

        logger.fine("KeyVaultWindowsDpapi, saveAllKeyRecords");
        // write encrypted file
        DpapiCipher cipher = new DpapiCipher(null);
        KeyVaultEncryptedFile file = new KeyVaultEncryptedFile(DPAPI_VAULT_ID);
        file.saveAllKeyRecordsToFile(cipher, mapKeyRecords, internalGetFilePath());

        // record file information
        fileModificationPoint();

        return SdkError.ISKEYVAULT_OK;
    }

    /**
     * Function that uses the KeyVaultFileModTracker to determine whether the key vault has changed
     * outside the context of this instance of the vault.
     * @return A KeyVaultFileModTracker.Result
     */
    private KeyVaultFileModTracker.Result fileModificationPoint() {

        // if we dont have a file tracker object, or we have changed the file we are tracking, then
        // create a new one here
        if (fileModTracker == null
            || !fileModTracker.getFilePath().equals(internalGetFilePath())) {

            fileModTracker = new KeyVaultFileModTracker(internalGetFilePath());
        }

        return fileModTracker.recordFileInfo();
    }
}
