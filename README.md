This is a class of VBscript functions that can be used for password hashing in Classic ASP.

There are 4 methods of password hashing included.

## 1. Standard password hashing
The users password is hashed using either MD5, SHA1, SHA256, SHA384 or SHA512 (MD5 and SHA1 should be avoided). A random salt is generated, the size of which is determined by the bit size of the specified hashing algorithm. A pepper is also added if specified. A hash string is returned containing all the information needed to verify against the original password.

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

### COM DLL installation:
Installation instructions for the various COM DLL's are available on their respective GitHub pages.

You will need root access to your server to install the COM DLL's. You can customize the Argon2, Bcrypt and PBKDF2 hashing parameters aswell as enabling/setting the pepper in the **Class_Initialize()** sub.

No changes need to be made to the code if you don't/can't install the DLL's, you just won't be able to call the Argon2/Bcrypt/PBKDF2 functions.

*****************************************************************************

### Setting a pepper (optional but recommended):

In Class_Initialize():

	use_pepper = true
	pepper = "Q[q|El^i@ngI7uj)>MCP<4w7^>r;)d" ' obvioulsy set your own, don't use this one
	
The pepper is a secret constant that should never change. For standard password hashing it is added to the users password along with the salt, however unlike the salt it is NOT included in the returned hash string. Instead a "~P" is included in the hash string to indicate to the verification function that the pepper was used.

If you're using a pepper make sure you keep a hard copy (printed off or saved to a memory stick and stored somewhere safe) just incase your code becomes corrupted or lost and needs rebuilding. If you lose your pepper you will not be able to verify passwords.

In the case of Argon2, Bcrypt and PBKDF2 the pepper is added to the password in the crypto class but the salt is generated within the COM DLL.

You can read more about peppers here: https://en.wikipedia.org/wiki/Pepper_(cryptography)

*****************************************************************************

### Standard password hashing example:

Class function:

	hashPassword([USERS PASSWORD],[HASHING ALGORITHM],[ENCODING])
	' Hashing algorithms supported are: MD5, SHA1, SHA256, SHA384 and SHA512
	' Encoding can be base64 (b64) or Hex
	
In VBscript for Classic ASP:

	set crypt = new crypto 

	response.write crypt.hashPassword("myPassword","SHA256","b64")
	
Output example:

	$SHA256~P$B64$DmP8L5wIyrNEpmA+zQJ2QeewczR3zK1XZqg36/vKAVQ=$A0kREThQ2dl/joc5YQqKaZq5Vh0pHAI1bFvStWJEkhw=
	
Execution time:

	0.0078s
	
Hash string structure:

	$[HASHING ALGORITHM]~[PEPPER INDICATOR]$[ENCODING]$[SALTED/PEPPERED PASSWORD HASH]$[RANDOM SALT]

Verification example:

	set crypt = new crypto

	response.write crypt.verifyPassword("myPassword","$SHA256~P$B64$DmP8L5wIyrNEpmA+zQJ2QeewczR3zK1XZqg36/vKAVQ=$A0kREThQ2dl/joc5YQqKaZq5Vh0pHAI1bFvStWJEkhw=")
	
Verification output:

	True
	
*****************************************************************************

### Argon2 password hashing example:

Parameters in Class_Initialize():

	a2_timeCost = 4 ' default: 4
	a2_memoryCost = 2048 ' default: 2048
	a2_lanes = 4 ' default: 4
	a2_threads = 4 ' default: Computers Processor Count
	a2_saltBytes = 16 ' default: 16

Class function:

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

Verification output:

	True
		
**NOTE:** The "~P" in the Argon2 hash indicates that a pepper was applied to the password before hashing. This is so the verification function knows to reapply the pepper. The "~P" is removed before the verification function calls the COM DLL.

*****************************************************************************

### Bcrypt password hashing example:

Parameters in Class_Initialize():

	Bcrypt_workFactor = 12 ' default: 10

Class function:

	hashPasswordBcrypt([USERS PASSWORD])
	
In VBscript for Classic ASP:

	set crypt = new crypto

	response.write crypt.hashPasswordBcrypt("myPassword")
	
Output example:

	$2a~P$12$s9THkLgv6bJU9Qio8Id2N.FpB79P5w4zdsHvzMAxHK/ht3KxQnsca
	
Execution time:

	0.4854s
	
Verification example:

	set crypt = new crypto
	
	response.write crypt.verifyPassword("myPassword","$2a~P$12$s9THkLgv6bJU9Qio8Id2N.FpB79P5w4zdsHvzMAxHK/ht3KxQnsca")

Verification output:

	True
		
**NOTE:** The "~P" in the Bcrypt hash indicates that a pepper was applied to the password before hashing. This is so the verification function knows to reapply the pepper. The "~P" is removed before the verification function calls the COM DLL.

*****************************************************************************

### PBKDF2 password hashing example:

Parameters in Class_Initialize():

	PBKDF2_iterations = 30000 ' default: 10000
	PBKDF2_alg = "sha512" ' default: sha1 | only sha1, sha256 and sha512 are supported
	PBKDF2_saltBytes = 16 ' default: 16
	PBKDF2_keyLength = 32 ' default: 32

Class function:

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

Verification output:

	True

**NOTE:** The PBKDF2 parameters and salt are contained within the base64 hash string.

**NOTE:** The "~P" in the PBKDF2 hash indicates that a pepper was applied to the password before hashing. This is so the verification function knows to reapply the pepper. The "~P" is removed before the verification function calls the COM DLL.


*****************************************************************************

Also included in the class is a function for computing HMAC keys, as well as a function for validating passwords against a regular expression string to ensure they meet a minimum entropy requirement. 

*****************************************************************************

I would personally recommend Bcrypt as the preferred password hashing algorithm with a work factor of 11 or 12 (don't go lower than 10). Depending on your server specs you could go higher than 12, but run some tests first and call the **crypto.execution_time()** function to gauge the average execution time.
