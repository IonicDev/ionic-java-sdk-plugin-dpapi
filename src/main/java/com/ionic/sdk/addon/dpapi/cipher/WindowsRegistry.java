package com.ionic.sdk.addon.dpapi.cipher;

import com.ionic.sdk.error.IonicException;
import com.ionic.sdk.error.SdkError;
import com.sun.jna.platform.win32.Advapi32Util;
import com.sun.jna.platform.win32.Win32Exception;
import com.sun.jna.platform.win32.WinError;
import com.sun.jna.platform.win32.WinNT;
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
        final WinReg.HKEYByReference hkeyRef = advapiRegistryGetKey(REGISTRY_KEY);
        try {
            return Advapi32Util.registryGetStringValue(hkeyRef.getValue(), REGISTRY_VALUE);
        } finally {
            advapiRegistryCloseKey(hkeyRef.getValue());
        }
    }

    /**
     * Retrieve a reference to the HKEY associated with the requested key path.
     *
     * @param key the path in the registry hive to the hkey
     * @return the hkey reference (according to jna documentation, caller is reponsible for closing it after use)
     * @throws IonicException on registry access failure
     */
    private static WinReg.HKEYByReference advapiRegistryGetKey(
            final String key) throws IonicException {
        final WinReg.HKEYByReference hkeyRef64 = advapiRegistryGetKey(key, WinNT.KEY_WOW64_64KEY);
        // WOW64 ignored on 32-bit OS
        // on 64-bit OS, 64 bit application talks to 64-bit registry by default
        // on 64-bit OS, 32 bit application talks to 32-bit registry by default
        // for versions if windows <=7? Reflection & redirection are the normal
        // and we don't have to do anything special.
        // But for Windows OS >= 8, no more reflection, so we must explicitly
        // ask for the correct registry.
        // Which really just means 32-bit applications on 64-bit os needs 64-bit registry.
        // try again for the 32-bit app on 64-bit OS case
        // try for 64 bit registry
        return (hkeyRef64 == null) ? advapiRegistryGetKey(REGISTRY_KEY, 0) : hkeyRef64;
    }

    /**
     * Retrieve a reference to the HKEY associated with the requested key path.  Both the WOW64 and the 32 bit
     * paths are checked for the hkey
     *
     * @param key        the path in the registry hive to the hkey
     * @param samBitness if set, this value should be OR'd with the access bit to specify the JNA API parameter
     * @return the hkey reference (according to jna documentation, caller is responsible for closing it after use)
     * @throws IonicException on registry access failure
     */
    private static WinReg.HKEYByReference advapiRegistryGetKey(
            final String key, final int samBitness) throws IonicException {
        try {
            return Advapi32Util.registryGetKey(WinReg.HKEY_LOCAL_MACHINE, key, WinNT.KEY_READ | samBitness);
        } catch (Win32Exception e) {
            if (e.getErrorCode() == WinError.ERROR_FILE_NOT_FOUND) {
                return null;
            } else {
                throw new IonicException(SdkError.ISAGENT_RESOURCE_NOT_FOUND, e);
            }
        }
    }

    /**
     * Call the JNA API to close the specified key.
     *
     * @param hkey the hkey to be closed
     */
    private static void advapiRegistryCloseKey(final WinReg.HKEY hkey) {
        Advapi32Util.registryCloseKey(hkey);
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
