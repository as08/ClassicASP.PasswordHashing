This is a class of VBscript functions that can be used for password hashing in Classic ASP.

There are 4 methods of password hashing included.

## 1. Standard password hashing
The users password is hashed using either MD5, SHA1, SHA256, SHA384 or SHA512 (MD5 and SHA1 should be avoided). A random salt is generated, the size of which is determined by the bit size of the specified hashing algorithm. A cryptographic pepper is also added if specified. A hash string is returned containing all the information needed to verify against the original password.

This method uses the System.Security.Cryptography class to perform the hashing and requires the .NET framework to be installed, which it is by default on all Windows Servers 2003+ **including** most shared hosting servers. (The standard password hashing function has been tested on GoDaddy's Shared Windows Hosting)

## 2. Argon2 (2i)
Argon2 is a key derivation function that was selected as the winner of the Password Hashing Competition in July 2015. It was designed by Alex Biryukov, Daniel Dinu, and Dmitry Khovratovich from the University of Luxembourg. Argon2i is optimized to resist side-channel attacks. It accesses the memory array in a password independent order.

This method requires a COM DLL to be installed. See: https://github.com/as08/ClassicASP.Argon2

## 3. Bcrypt
Bcrypt is a password hashing function designed by Niels Provos and David Mazières, based on the Blowfish cipher, and presented at USENIX in 1999. Besides incorporating a salt to protect against rainbow table attacks, bcrypt is an adaptive function: over time, the iteration count can be increased to make it slower, so it remains resistant to brute-force search attacks even with increasing computation power.

This method requires a COM DLL to be installed. See: https://github.com/as08/ClassicASP.Bcrypt

## 4. PBKDF2
PBKDF2 (Password-Based Key Derivation Function 2) is key derivation function with a sliding computational cost, aimed to reduce the vulnerability of encrypted keys to brute force attacks. RFC 8018 recommends PBKDF2 for password hashing

This method requires a COM DLL to be installed. See: https://github.com/as08/ClassicASP.PBKDF2

*****************************************************************************

You will need root access to your server to install the COM DLL's. You can customize the Argon2, Bcrypt and PBKDF2 hashing parameters aswell as enabling/setting the pepper in the **Class_Initialize()** sub.

No changes need to be made to the code if you don't/can't install the DLL's, you just won't be able to call the Argon2/Bcrypt/PBKDF2 functions.

*****************************************************************************

### Standard password hashing example:

	hashPassword([USERS PASSWORD],[HASHING ALGORITHM],[ENCODING])
	
In VBscript for Classic ASP:

	set crypt = new crypto 

	response.write crypt.hashPassword("myPassword","SHA256","b64") ' encoding can also be hex
	
Output example:

	$SHA256~P$B64$DmP8L5wIyrNEpmA+zQJ2QeewczR3zK1XZqg36/vKAVQ=$A0kREThQ2dl/joc5YQqKaZq5Vh0pHAI1bFvStWJEkhw=
	
Execution time:

	0.0078s
	
Hash string structure:

	$[HASHING ALGORITHM]~[PEPPER INDICATOR]$[ENCODING]$[SALTED/PEPPERED PASSWORD HASH]$[RANDOM SALT]

Verification example:

	set crypt = new crypto

	response.write crypt.verifyPassword("myPassword","$SHA256~P$B64$DmP8L5wIyrNEpmA+zQJ2QeewczR3zK1XZqg36/vKAVQ=$A0kREThQ2dl/joc5YQqKaZq5Vh0pHAI1bFvStWJEkhw=")
	
Output:

	True
	
*****************************************************************************

### Argon2 password hashing example:

	hashPasswordArgon2([USERS PASSWORD])
	
In VBscript for Classic ASP:

	set crypt = new crypto

	response.write crypt.hashPasswordArgon2("myPassword")
	
Output example:

	$argon2i~P$v=19$m=2048,t=4,p=4$N5yT2b+RtHdYQo4/wND/yA==$QVkCxOLyBh9evOxf117BWrE+XgzSrrA4y1okUQCUW/w=
	
Execution time:

	0.1250s
	
Verification example:

	set crypt = new crypto
	
	response.write crypt.verifyPassword("myPassword","$argon2i~P$v=19$m=2048,t=4,p=4$N5yT2b+RtHdYQo4/wND/yA==$QVkCxOLyBh9evOxf117BWrE+XgzSrrA4y1okUQCUW/w=")

Output:

	True
		
**NOTE:** The "~P" in the Argon2 hash indicates that a pepper was applied to the password before hashing. This is so the verification function knows to reapply the pepper. The "~P" is removed before the verification function calls the COM DLL.

*****************************************************************************

### Bcrypt password hashing example:

	hashPasswordBcrypt([USERS PASSWORD])
	
In VBscript for Classic ASP:

	set crypt = new crypto

	response.write crypt.hashPasswordBcrypt("myPassword")
	
Output example:

	$2a~P$10$s9THkLgv6bJU9Qio8Id2N.FpB79P5w4zdsHvzMAxHK/ht3KxQnsca
	
Execution time:

	0.4854s
	
Verification example:

	set crypt = new crypto
	
	response.write crypt.verifyPassword("myPassword","$2a~P$10$s9THkLgv6bJU9Qio8Id2N.FpB79P5w4zdsHvzMAxHK/ht3KxQnsca")

Output:

	True
		
**NOTE:** The "~P" in the Bcrypt hash indicates that a pepper was applied to the password before hashing. This is so the verification function knows to reapply the pepper. The "~P" is removed before the verification function calls the COM DLL.

*****************************************************************************

### PBKDF2 password hashing example:

	hashPasswordPBKDF2([USERS PASSWORD])
	
In VBscript for Classic ASP:

	set crypt = new crypto

	response.write crypt.hashPasswordPBKDF2("myPassword")
	
Output example:

	$PBKDF2~P$AQAAAAIAAHUwAAAAEOLUzLqiYYJqzZJVVDOOJuIBYmleusTd31QfXC6YAjFqPFnSdzFns+pnqSWe8qvvLg==
	
Execution time:

	0.1992s
	
Verification example:

	set crypt = new crypto
	
	response.write crypt.verifyPassword("myPassword","$PBKDF2~P$AQAAAAIAAHUwAAAAEOLUzLqiYYJqzZJVVDOOJuIBYmleusTd31QfXC6YAjFqPFnSdzFns+pnqSWe8qvvLg==")

Output:

	True

**NOTE:** The PBKDF2 parameters are contained within the base64 hash string.

**NOTE:** The "~P" in the PBKDF2 hash indicates that a pepper was applied to the password before hashing. This is so the verification function knows to reapply the pepper. The "~P" is removed before the verification function calls the COM DLL.


*****************************************************************************

Also included in the class is a function for computing HMAC keys, as well as a function for validating passwords against a regular expression string to ensure they meet a minimum entropy requirement. 
