package com.ionic.sdk.addon.dpapi.device.profile.persistor;

import com.ionic.sdk.core.value.Value;
import com.ionic.sdk.error.IonicException;
import com.ionic.sdk.error.SdkData;
import com.ionic.sdk.error.SdkError;
import com.ionic.sdk.json.JsonIO;
import com.ionic.sdk.json.JsonSource;
import com.ionic.sdk.json.JsonTarget;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;

/**
 * Utility class for manipulating device profile byte streams.
 */
public final class DeviceProfileUtils {

    /**
     * Constructor.
     * http://checkstyle.sourceforge.net/config_design.html#FinalClass
     */
    private DeviceProfileUtils() {
    }

    /**
     * Given a version string, fabricate a JSON device profile header specifying that version.
     *
     * @param version the device profile header version
     * @return a JSON formatted string, suitable for use as a device profile header
     */
    public static String createHeader(final String version) {
        final JsonObjectBuilder builder = Json.createObjectBuilder();
        JsonTarget.addNotNull(builder, HEADER_FIELD_FILE_TYPE_ID, HEADER_VALUE_FILE_TYPE_ID);
        JsonTarget.addNotNull(builder, HEADER_FIELD_FORMAT, HEADER_VALUE_FORMAT);
        JsonTarget.addNotNull(builder, HEADER_FIELD_VERSION, version);
        return JsonIO.write(builder.build(), false);
    }

    /**
     * Given a device profile header string, perform validation on the string.
     *
     * @param header a device profile header string (JSON)
     * @return the version specified in the device profile header
     * @throws IonicException on input JSON which cannot be parsed, or on invalid header type data
     */
    public static String getHeaderVersion(final String header) throws IonicException {
        String version = null;
        if (header != null) {
            final JsonObject jsonObject = JsonIO.readObject(header, SdkError.ISAGENT_PARSEFAILED);
            final String fileTypeId = JsonSource.getString(jsonObject, HEADER_FIELD_FILE_TYPE_ID);
            final String format = JsonSource.getString(jsonObject, HEADER_FIELD_FORMAT);
            version = JsonSource.getString(jsonObject, HEADER_FIELD_VERSION);
            final boolean isOkFileTypeId = Value.isEqual(HEADER_VALUE_FILE_TYPE_ID, fileTypeId);
            final boolean isOkFormat = Value.isEqual(HEADER_VALUE_FORMAT, format);
            SdkData.checkTrue(isOkFileTypeId, SdkError.ISAGENT_INVALIDVALUE, HEADER_FIELD_FILE_TYPE_ID);
            SdkData.checkTrue(isOkFormat, SdkError.ISAGENT_INVALIDVALUE, HEADER_FIELD_FORMAT);
        }
        return version;
    }

    /**
     * Ionic Secure Enrollment Profile type header field name.
     */
    private static final String HEADER_FIELD_FILE_TYPE_ID = "fileTypeId";

    /**
     * Ionic Secure Enrollment Profile type header field value.
     */
    private static final String HEADER_VALUE_FILE_TYPE_ID = "ionic-device-profiles";

    /**
     * Ionic Secure Enrollment Profile type header field name.
     */
    private static final String HEADER_FIELD_FORMAT = "format";

    /**
     * Ionic Secure Enrollment Profile type header field value.
     */
    private static final String HEADER_VALUE_FORMAT = "dpapi";

    /**
     * Ionic Secure Enrollment Profile type header field name.
     */
    private static final String HEADER_FIELD_VERSION = "version";
}
