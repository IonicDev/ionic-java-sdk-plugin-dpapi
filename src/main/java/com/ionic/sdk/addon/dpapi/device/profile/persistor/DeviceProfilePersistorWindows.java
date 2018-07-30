package com.ionic.sdk.addon.dpapi.device.profile.persistor;

import com.ionic.sdk.core.value.Value;
import com.ionic.sdk.core.vm.VM;
import com.ionic.sdk.device.DeviceUtils;
import com.ionic.sdk.device.profile.DeviceProfile;
import com.ionic.sdk.device.profile.persistor.DeviceProfilePersistorBase;
import com.ionic.sdk.error.IonicException;
import com.ionic.sdk.error.SdkData;
import com.ionic.sdk.error.SdkError;

import java.io.File;
import java.util.List;

/**
 * DeviceProfilePersistorWindows brokers access to a persisted Ionic Secure Enrollment Profile, protected using the
 * Windows Data Protection API.
 */
public final class DeviceProfilePersistorWindows extends DeviceProfilePersistorBase {

    /**
     * The persistor format version preference specified by the user.
     */
    private String formatVersionOverride;

    /**
     * Default constructor for DeviceProfilePersistorDPAPI.
     *
     * @throws IonicException on instantiation in the context of a non-Windows operating system
     */
    public DeviceProfilePersistorWindows() throws IonicException {
        super(getDefaultFile().getPath(), null);
        SdkData.checkTrue(VM.isWindows(), SdkError.ISAGENT_NOTIMPLEMENTED, VM.getOsName());
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
        final byte[] bytes = DeviceUtils.read(new File(getFilePath()));
        final DeviceProfileSerializer serializer = new DeviceProfileSerializer(bytes);
        final String versionLoad = DeviceProfileUtils.getHeaderVersion(serializer.getHeader());
        final boolean isV11 = DeviceProfilePersistorWindowsV11.HEADER_VALUE_VERSION.equals(versionLoad);
        final DeviceProfilePersistorBase persistor = isV11
                ? new DeviceProfilePersistorWindowsV11()
                : new DeviceProfilePersistorWindowsV10();
        persistor.setFilePath(getFilePath());
        return persistor.loadAllProfiles(activeProfile);
    }

    /**
     * Serialize Secure Enrollment Profile data to the filesystem.
     * <p>
     * Unless otherwise specified (via {@link #setFormatVersionOverride(String)}), v1.0 of the Windows persistor
     * is used by default.
     * <p>
     * To specify v1.1, use setFormatVersionOverride with parameter
     * {@link DeviceProfilePersistorWindowsV11#HEADER_VALUE_VERSION}.
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
        final boolean isV11 = DeviceProfilePersistorWindowsV11.HEADER_VALUE_VERSION.equals(versionSave);
        final DeviceProfilePersistorBase persistor = isV11
                ? new DeviceProfilePersistorWindowsV11()
                : new DeviceProfilePersistorWindowsV10();
        persistor.setFilePath(getFilePath());
        persistor.saveAllProfiles(profiles, activeProfile);
    }

    /**
     * The Windows OS default Secure Enrollment Profile is stored in a specific place on the filesystem.
     *
     * @return the File containing the Secure Enrollment Profile data for the current user
     */
    static File getDefaultFile() {
        final File folderUserHome = new File(System.getProperty(VM.Sys.USER_HOME));
        final File folderIonic = new File(folderUserHome, USER_FOLDER_IONIC);
        return new File(folderIonic, FILENAME_SEP);
    }

    /**
     * The folder, relative to USER PROFILE DIR, in which the default Ionic SEP is stored.
     */
    private static final String USER_FOLDER_IONIC = "AppData/LocalLow/IonicSecurity";

    /**
     * The name of the file in USER_FOLDER_IONIC, in which the default Ionic SEP is stored.
     */
    private static final String FILENAME_SEP = "DeviceProfiles.dat";
}
