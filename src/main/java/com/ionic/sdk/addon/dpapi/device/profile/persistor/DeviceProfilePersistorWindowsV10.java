package com.ionic.sdk.addon.dpapi.device.profile.persistor;

import com.ionic.sdk.addon.dpapi.cipher.DpapiCipher;
import com.ionic.sdk.addon.dpapi.cipher.WindowsRegistry;
import com.ionic.sdk.core.vm.VM;
import com.ionic.sdk.device.profile.persistor.DeviceProfilePersistorBase;
import com.ionic.sdk.error.IonicException;
import com.ionic.sdk.error.SdkData;
import com.ionic.sdk.error.SdkError;

/**
 * DeviceProfilePersistorWindowsV10 brokers access to a persisted Ionic Secure Enrollment Profile, protected using
 * the Windows Data Protection API.  The persisted file is serialized with no header information, in a manner
 * analogous to {@link com.ionic.sdk.device.profile.persistor.DeviceProfilePersistorAesGcm} and
 * {@link com.ionic.sdk.device.profile.persistor.DeviceProfilePersistorPassword}.
 */
public class DeviceProfilePersistorWindowsV10 extends DeviceProfilePersistorBase {

    /**
     * Default constructor for DeviceProfilePersistorDPAPI.  The DPAPI user profile key will be used for encryption
     * operations.
     *
     * @throws IonicException on instantiation in the context of a non-Windows operating system
     */
    public DeviceProfilePersistorWindowsV10() throws IonicException {
        this(true);
    }

    /**
     * Constructor for DeviceProfilePersistorDPAPI.
     *
     * @param isUser true if DPAPI user profile key is to be used; false if the DPAPI machine key is to be used
     * @throws IonicException on instantiation in the context of a non-Windows operating system
     */
    public DeviceProfilePersistorWindowsV10(final boolean isUser) throws IonicException {
        super(DeviceProfilePersistorWindows.getDefaultFile().getPath(),
                new DpapiCipher(WindowsRegistry.getMachineGuid(), isUser));
        SdkData.checkTrue(VM.isWindows(), SdkError.ISAGENT_NOTIMPLEMENTED, VM.getOsName());
    }

    @Override
    protected final String getFormat() {
        return DeviceProfilePersistorWindows.FORMAT_DPAPI;
    }
}
