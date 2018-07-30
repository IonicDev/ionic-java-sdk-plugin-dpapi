package com.ionic.sdk.addon.dpapi.device.profile.persistor;

import com.ionic.sdk.addon.dpapi.cipher.DpapiCipher;
import com.ionic.sdk.core.codec.Transcoder;
import com.ionic.sdk.core.datastructures.Tuple;
import com.ionic.sdk.core.io.Stream;
import com.ionic.sdk.core.vm.VM;
import com.ionic.sdk.device.profile.DeviceProfile;
import com.ionic.sdk.device.profile.persistor.DeviceProfilePersistorBase;
import com.ionic.sdk.error.IonicException;
import com.ionic.sdk.error.SdkData;
import com.ionic.sdk.error.SdkError;

import javax.json.JsonObject;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.util.List;

/**
 * DeviceProfilePersistorWindowsV11 brokers access to a persisted Ionic Secure Enrollment Profile, protected using
 * the Windows Data Protection API.  The persisted file is serialized with a JSON type header prepended to the data.
 */
public class DeviceProfilePersistorWindowsV11 extends DeviceProfilePersistorBase {

    /**
     * Default constructor for DeviceProfilePersistorDPAPI.
     *
     * @throws IonicException on instantiation in the context of a non-Windows operating system
     */
    public DeviceProfilePersistorWindowsV11() throws IonicException {
        super(DeviceProfilePersistorWindows.getDefaultFile().getPath(), new DpapiCipher(null));
        SdkData.checkTrue(VM.isWindows(), SdkError.ISAGENT_NOTIMPLEMENTED, VM.getOsName());
    }

    /**
     * Deserialize Secure Enrollment Profile data from the filesystem.
     * <p>
     * This method is overridden in order to handle processing of the v1.1 json type header.  The subsequent byte
     * stream is handled by the base implementation.
     *
     * @param activeProfile an out parameter that will provide the persisted active profile
     * @return the list of persisted device profiles
     * @throws IonicException if v1.1 json header is not present, expect ISAGENT_ERROR
     *                        decrypt or json parsing can throw a sdk exception, expect
     *                        ISAGENT_PARSEFAILED, ISAGENT_MISSINGVALUE, ISAGENT_RESOURCE_NOT_FOUND,
     *                        or ISCRYPTO_ERROR
     */
    @Override
    public final List<DeviceProfile> loadAllProfiles(final String[] activeProfile) throws IonicException {
        try {
            final byte[] bytes = Stream.read(new File(getFilePath()));
            final DeviceProfileSerializer serializer = new DeviceProfileSerializer(bytes);
            SdkData.checkTrue((serializer.getHeader() != null), SdkError.ISAGENT_ERROR, JsonObject.class.getName());
            final String version = DeviceProfileUtils.getHeaderVersion(serializer.getHeader());
            SdkData.checkTrue(HEADER_VALUE_VERSION.equals(version), SdkError.ISAGENT_ERROR, version);
            final Tuple<List<DeviceProfile>, String> profiles =
                    loadAllProfilesFromJson(serializer.getBody(), getCipher());
            activeProfile[0] = profiles.second();
            return profiles.first();
        } catch (IOException e) {
            throw new IonicException(e);
        }
    }

    /**
     * Serialize Secure Enrollment Profile data to the filesystem.
     * <p>
     * This method is overridden in order to handle processing of the v1.1 json type header.  The subsequent byte
     * stream is handled by the base implementation.
     *
     * @param profiles      change the list of available profiles to this input parameter.
     * @param activeProfile change the active device profile to this input parameter.
     * @throws IonicException write to disk can throw a ISAGENT_OPENFILE exception
     *                        saveAllProfilesToJson can throw an ISCRYPTO_ERROR on encrypt.
     */
    @Override
    public final void saveAllProfiles(
            final List<DeviceProfile> profiles, final String activeProfile) throws IonicException {
        final String header = DeviceProfileUtils.createHeader(HEADER_VALUE_VERSION);
        try {
            ByteArrayOutputStream os = new ByteArrayOutputStream();
            os.write(Transcoder.utf8().decode(header));
            os.write(Transcoder.utf8().decode(DeviceProfileSerializer.HEADER_JSON_DELIMITER));
            os.write(saveAllProfilesToJson(profiles, activeProfile, getCipher()));
            Stream.write(new File(getFilePath()), os.toByteArray());
        } catch (IOException e) {
            throw new IonicException(e);
        }
    }

    /**
     * Ionic Secure Enrollment Profile type header field value.
     */
    public static final String HEADER_VALUE_VERSION = "1.1";
}
