# ionic-java-sdk-plugin-dpapi
[Ionic](https://ionic.com) Java software development kit (SDK) plugin library.  This plugin library interfaces with 
the Data Protection API (DPAPI), a service provided by the Microsoft Windows operating system.  The service
provides data protection functionality by using user or machine credentials to encrypt or decrypt data.
  
This plugin library code depends on the Ionic Java SDK.
* [source code (github.com)](https://github.com/IonicDev/ionic-java-sdk)
* [distributables (repo.maven.apache.org)](https://repo.maven.apache.org/maven2/com/ionic/ionic-sdk/2.7.0/)

### Points of Interest
* ```DeviceProfilePersistorWindows``` is an implementation of ```ProfilePersistor``` allowing for filesystem storage 
of a Machina device enrollment protected by DPAPI.
* ```KeyVaultWindowsDpapi``` is an implementation of ```KeyVaultBase``` providing a local cache of KeyServices 
cryptography keys protected by DPAPI.

