# PyWallet
A Python Module for signing and verifying Apple Wallet Passbooks


````python

from PKPass import PKPass


if __name__ == "__main__":
	pkpass = PKPass(pass_directory_path="./Passes/SamplePass.pass")
	pkpass.sign(key="./Certs/Key.p12", cert="./Certs/AppleWWDR.pem", password="")
	pkpass.compress("./Passes/SamplePass.pkpass")

````
