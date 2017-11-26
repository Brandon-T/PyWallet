# PyWallet
A Python Module for signing and verifying Apple Wallet Passbooks

## Getting the certificates

1) Get a Pass Type Id

* Visit the iOS Provisioning Portal -> Pass Type IDs -> New Pass Type ID
* Select pass type id -> Configure (Follow steps and download generated pass.cer file)
* Import downloaded certificate into Keychain Access on your Mac.
* Export the certificate from Keychain Access into a ".p12" file (In "Usage" section below this file is referenced as "Key.p12")

2) Get Apple WWDR Certificate
* Certificate is available at: http://developer.apple.com/certificationauthority/AppleWWDRCA.cer
* Convert it into a ".pem" file (In "Usage" section below this file is referenced as "AppleWWDR.pem""):
```shell
	$ openssl x509 -inform der -in AppleWWDRCA.cer -out AppleWWDRCA.pem
```

3) Get PassKit support materials and sample Pass data from Apple
* https://developer.apple.com/services-account/download?path=/iOS/Wallet_Support_Materials/WalletCompanionFiles.zip

## Installing required libraries

Mac:
```shell
    $ brew install openssl
    $ brew upgrade openssl    
```
Ubuntu/Linux:
```shell
    $ apt-get install openssl
    $ apt-get upgrade openssl    
```

## Using PyWallet tool:
````python

from PKPass import PKPass
import CertSign

if __name__ == "__main__":
    
    CertSign.initializeOpenSSL()
    
    pkpass = PKPass(pass_directory_path="./Passes/SamplePass.pass")
    pkpass.sign(key="./Certs/Key.p12", cert="./Certs/AppleWWDR.pem", password="")
    pkpass.compress("./Passes/SamplePass.pkpass")
	
    CertSign.freeOpenSSL()
````

