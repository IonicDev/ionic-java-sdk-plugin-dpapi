package com.ionic.sdk.addon.dpapi.device.profile.persistor;

import com.ionic.sdk.core.value.Value;
import com.ionic.sdk.core.vm.VM;
import com.ionic.sdk.device.DeviceUtils;
import com.ionic.sdk.device.profile.DeviceProfile;
import com.ionic.sdk.device.profile.persistor.DeviceProfilePersistorBase;
import com.ionic.sdk.device.profile.persistor.DeviceProfileSerializer;
import com.ionic.sdk.error.IonicException;
import com.ionic.sdk.error.SdkData;
import com.ionic.sdk.error.SdkError;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * DeviceProfilePersistorWindows brokers access to a persisted Ionic Secure Enrollment Profile, protected using the
 * Windows Data Protection API.
 * <p>
 * The Windows filesystem includes a user profile folder.  The default filesystem location of the Ionic Security SEP
 * may be found in either the "Roaming" or "LocalLow" subfolders within the user profile folder.
 * <ol>
 * <li>New Secure Enrollment Profiles are persisted within the "Roaming" folder.</li>
 * <li>If the "LocalLow" legacy filesystem location is already in use on a machine, that existing file will be
 * updated.</li>
 * </ol>
 * <p>
 * The file in use may also be updated using the {@link #setFilePath(String)} API.
 */
public final class DeviceProfilePersistorWindows extends DeviceProfilePersistorBase {

    /**
     * Flag indicating whether or not access to protected content should be scoped to protecting user.  If true,
     * the DPAPI user profile key is to be used; otherwise, the DPAPI machine key will be used.
     */
    private final boolean isUser;

    /**
     * The persistor format version preference specified by the user.
     */
    private String formatVersionOverride;

    /**
     * Default constructor for DeviceProfilePersistorDPAPI.  The DPAPI user profile key will be used for encryption
     * operations.
     *
     * @throws IonicException on instantiation in the context of a non-Windows operating system
     */
    public DeviceProfilePersistorWindows() throws IonicException {
        this(true);
    }

    /**
     * Constructor for DeviceProfilePersistorDPAPI.
     *
     * @param isUser true if DPAPI user profile key is to be used; false if the DPAPI machine key is to be used
     * @throws IonicException on instantiation in the context of a non-Windows operating system
     */
    public DeviceProfilePersistorWindows(final boolean isUser) throws IonicException {
        super(getDefaultFile().getPath(), null);
        SdkData.checkTrue(VM.isWindows(), SdkError.ISAGENT_NOTIMPLEMENTED, VM.getOsName());
        this.isUser = isUser;
    }

    @Override
    protected String getFormat() {
        return FORMAT_DPAPI;
    }

    /**
     * @return the persistor format version preference specified by the user
     */
    public String getFormatVersionOverride() {
        return formatVersionOverride;
    }

    /**
     * Set the persistor format version preference.  This allows specification of a serialization format different
     * than the default v1.0 format.
     *
     * @param formatVersionOverride the persistor format version preference
     */
    public void setFormatVersionOverride(final String formatVersionOverride) {
        this.formatVersionOverride = formatVersionOverride;
    }

    /**
     * Deserialize Secure Enrollment Profile data from the filesystem.
     * <p>
     * Attempt first to load using the v1.1 DPAPI persistor.  If this fails, fallback to the v1.0 persistor.
     *
     * @param activeProfile an out parameter that will provide the persisted active profile
     * @return the list of persisted device profiles
     * @throws IonicException if v1.1 json header is not present, expect ISAGENT_ERROR
     *                        decrypt or json parsing can throw a sdk exception, expect
     *                        ISAGENT_PARSEFAILED, ISAGENT_MISSINGVALUE, ISAGENT_RESOURCE_NOT_FOUND,
     *                        or ISCRYPTO_ERROR
     */
    @Override
    public List<DeviceProfile> loadAllProfiles(final String[] activeProfile) throws IonicException {
        final File file = new File(getFilePath());
        final List<DeviceProfile> deviceProfiles;
        if (file.exists()) {
            final byte[] bytes = DeviceUtils.read(file);
            final DeviceProfileSerializer serializer = new DeviceProfileSerializer(bytes);
            final String versionLoad = DeviceProfileUtils.getHeaderVersion(serializer.getHeader());
            final boolean isV11 = DeviceProfilePersistorWindowsV11.VERSION_1_1.equals(versionLoad);
            final DeviceProfilePersistorBase persistor = isV11
                    ? new DeviceProfilePersistorWindowsV11(isUser)
                    : new DeviceProfilePersistorWindowsV10(isUser);
            persistor.setFilePath(getFilePath());
            deviceProfiles = persistor.loadAllProfiles(activeProfile);
        } else {
            activeProfile[0] = "";
            deviceProfiles = new ArrayList<DeviceProfile>();
        }
        return deviceProfiles;
    }

    /**
     * Serialize Secure Enrollment Profile data to the filesystem.
     * <p>
     * Unless otherwise specified (via {@link #setFormatVersionOverride(String)}), v1.0 of the Windows persistor
     * is used by default.
     * <p>
     * To specify v1.1, use setFormatVersionOverride with parameter
     * {@link DeviceProfilePersistorWindowsV11#VERSION_1_1}.
     * <p>
     * Version 1.1 provides for a json type header that describes the file content.  The subsequent byte
     * stream is handled by the base implementation, {@link DeviceProfilePersistorBase}.
     *
     * @param profiles      change the list of available profiles to this input parameter.
     * @param activeProfile change the active device profile to this input parameter.
     * @throws IonicException write to disk can throw a ISAGENT_OPENFILE exception
     *                        saveAllProfilesToJson can throw an ISCRYPTO_ERROR on encrypt.
     */
    @Override
    public void saveAllProfiles(final List<DeviceProfile> profiles, final String activeProfile) throws IonicException {
        String versionSave = null;
        final File file = new File(getFilePath());
        if (file.exists()) {
            final byte[] bytes = DeviceUtils.read(file);
            final DeviceProfileSerializer serializer = new DeviceProfileSerializer(bytes);
            final String versionActual = DeviceProfileUtils.getHeaderVersion(serializer.getHeader());
            if (!Value.isEmpty(versionActual)) {
                versionSave = versionActual;
            }
        }
        if (!Value.isEmpty(formatVersionOverride)) {
            versionSave = formatVersionOverride;
        }
        if (Value.isEmpty(versionSave)) {
            versionSave = getVersion();
        }
        final boolean isV11 = DeviceProfilePersistorWindowsV11.VERSION_1_1.equals(versionSave);
        final DeviceProfilePersistorBase persistor = isV11
                ? new DeviceProfilePersistorWindowsV11(isUser)
                : new DeviceProfilePersistorWindowsV10(isUser);
        persistor.setFilePath(file.getPath());
        persistor.saveAllProfiles(profiles, activeProfile);
    }

    /**
     * The Windows OS default Secure Enrollment Profile is stored in a specific place on the filesystem.
     *
     * @return the File containing the Secure Enrollment Profile data for the current user
     */
    static File getDefaultFile() {
        final File folderUserHome = new File(System.getProperty(VM.Sys.USER_HOME));
        final File folderIonicLocalLow = new File(folderUserHome, USER_FOLDER_IONIC_LOCAL_LOW);
        final File fileSEPLocalLow = new File(folderIonicLocalLow, FILENAME_SEP);
        final File folderIonicRoaming = new File(folderUserHome, USER_FOLDER_IONIC_ROAMING);
        final File fileSEPRoaming = new File(folderIonicRoaming, FILENAME_SEP);
        final boolean isLocalLow = fileSEPLocalLow.exists();
        final boolean isRoaming = fileSEPRoaming.exists();
        // per SDK-2082:
        // Check Roaming first, check LocalLow.  Remember where we found it for saving, or default to Roaming."
        return isRoaming ? fileSEPRoaming : (isLocalLow ? fileSEPLocalLow : fileSEPRoaming);
    }

    /**
     * The folder, relative to USER PROFILE DIR, in which the default Ionic SEP is stored.
     */
    private static final String USER_FOLDER_IONIC_LOCAL_LOW = "AppData/LocalLow/IonicSecurity";

    /**
     * The folder, relative to USER PROFILE DIR, in which the default Ionic SEP is stored.
     */
    private static final String USER_FOLDER_IONIC_ROAMING = "AppData/Roaming/Ionic Security";

    /**
     * The name of the file in USER_FOLDER_IONIC, in which the default Ionic SEP is stored.
     */
    private static final String FILENAME_SEP = "DeviceProfiles.dat";

    /**
     * Ionic Secure Enrollment Profile type header field value.
     */
    public static final String FORMAT_DPAPI = "dpapi";
}
