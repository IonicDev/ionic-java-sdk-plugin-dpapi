package com.ionic.sdk.addon.dpapi.cipher;

import com.ionic.sdk.error.IonicException;
import com.ionic.sdk.error.SdkError;
import com.sun.jna.platform.win32.Advapi32Util;
import com.sun.jna.platform.win32.Win32Exception;
import com.sun.jna.platform.win32.WinReg;

/**
 * Provide access to Windows HKLM MachineGuid, used by version 1.0 of
 * {@link com.ionic.sdk.addon.dpapi.device.profile.persistor.DeviceProfilePersistorWindows} to protect access
 * to serialized Secure Enrollment Profile (SEP).
 */
public final class WindowsRegistry {

    /**
     * Constructor.
     * http://checkstyle.sourceforge.net/config_design.html#FinalClass
     */
    private WindowsRegistry() {
    }

    /**
     * Retrieve the machine GUID, which may be used by the DPAPI protection scheme.
     *
     * @return the string representation of the machine guid
     * @throws IonicException on inability to access the registry, or the specified value from within the registry
     */
    public static String getMachineGuid() throws IonicException {
        try {
            return Advapi32Util.registryGetStringValue(
                    WinReg.HKEY_LOCAL_MACHINE, REGISTRY_KEY, REGISTRY_VALUE);
        } catch (Win32Exception e) {
            throw new IonicException(SdkError.ISAGENT_RESOURCE_NOT_FOUND, e);
        }
    }

    /**
     * The registry key in the hive HKEY_LOCAL_MACHINE in which the machine GUID is stored.
     */
    private static final String REGISTRY_KEY = "SOFTWARE\\Microsoft\\Cryptography";

    /**
     * The name of the registry value containing the machine GUID is stored.
     */
    private static final String REGISTRY_VALUE = "MachineGuid";
}
