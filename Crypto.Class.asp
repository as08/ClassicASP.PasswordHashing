<%

    class crypto

        private use_pepper
        private pepper
        private crypto_start
        private a2_timeCost
        private a2_memoryCost
        private a2_lanes
        private a2_threads
        private a2_saltBytes
        private Bcrypt_workFactor
        private PBKDF2_iterations
        private PBKDF2_alg
        private PBKDF2_saltBytes
        private PBKDF2_keyLength

        Private Sub Class_Initialize()

            ' The use of a pepper is optional, to disable set "use_pepper" to false.

            ' You can read more about peppers here: 
            ' https://en.wikipedia.org/wiki/Pepper_(cryptography)

            ' If you set a pepper It's good practice to keep a hard copy should your code 
            ' become corrupted or lost and needs rebuilding

            use_pepper = true
            pepper = "xxxxxxxxxxxxxxxx" ' change to a secret random string

            ' Argon 2 parameters

            ' Defaults used by ClassicASP.Argon2 if none specified:

            ' timeCost = 4
            ' memoryCost = 2048
            ' lanes = 4
            ' threads = Processor Count
            ' salt length = 16 bytes

            a2_timeCost = 4
            a2_memoryCost = 2048
            a2_lanes = 4
            a2_threads = 4
            a2_saltBytes = 16

            ' Bcrypt default work factor, between 4 and 31. 
            ' 10 is used as default if no work factor is specified

            Bcrypt_workFactor = 12

            ' PBKDF2 parameters

            ' Defaults used by ClassicASP.PBKDF2 if none specified:

            ' PBKDF2_iterations = 10000
            ' PBKDF2_alg = sha1
            ' PBKDF2_saltBytes = 16 bytes
            ' PBKDF2_keyLength = 32 bytes

            PBKDF2_iterations = 30000
            PBKDF2_alg = "sha512" ' only sha1, sha256 and sha512 are supported
            PBKDF2_saltBytes = 16
            PBKDF2_keyLength = 32

            crypto_start = Timer() 

        end sub

        public function hashPassword(ByVal pass, ByVal alg, ByVal encoding)

            Dim algBytes, salt, pi

            ' Caclculate the salt byte length and generate

            algBytes = int(len(hash("",alg,"hex"))/2)
            salt = randomBytes(algBytes)

            ' Hash the password

            if use_pepper then

                ' Append an "~P" to the algorithm name when outputting the hash 
                ' string to indicate that the pepper was used. This is so the 
                ' verify function knows to apply the pepper even if use_pepper 
                ' is changed to false.

                pass = pepper & pass & salt
                pi = "~P"

            else

                pass = pass & salt
                pi = ""  

            end if

            if lCase(encoding) = "base64" then encoding = "b64"

            hashPassword =  "$" & uCase(alg & pi) &_ 
                            "$" & uCase(encoding) &_ 
                            "$" & hash(pass,alg,encoding) &_ 
                            "$" & encodeSalt(salt,encoding)

        end function

        public function hashPasswordArgon2(ByVal password)

            ' See https://github.com/as08/ClassicASP.Argon2 for installation instructions.

            Dim agron2 : set agron2 = server.CreateObject("ClassicASP.Argon2")

                ' Apply the pepper to the end of the password if specified

                if use_pepper then password = password & pepper

                hashPasswordArgon2 =    agron2.hash(_
                                        password,_
                                        a2_timeCost,_
                                        a2_memoryCost,_
                                        a2_lanes,_
                                        a2_threads,_
                                        a2_saltBytes)

                if use_pepper then

                    ' Alter the argon2 hash to indicate that the pepper was used.
                    ' This will be removed before verifying

                    hashPasswordArgon2 = replace(hashPasswordArgon2,"$argon2i","$argon2i~P",1,-1,1)

                end if

            ' or to use the default parameters:
            ' hashPasswordArgon2 = agron2.hash(password)

            set agron2 = nothing

        end function

        public function hashPasswordBcrypt(ByVal password)

            ' See https://github.com/as08/ClassicASP.Bcrypt for installation instructions.

            Dim Bcrypt : set Bcrypt = server.CreateObject("ClassicASP.Bcrypt")

                ' Apply the pepper to the end of the password if specified.
                ' Bcrypt can only hash a maximum of 72 bytes, so it makes 
                ' more sense to add the pepper at the end rather than the
                ' beginning of the password

                if use_pepper then password = password & pepper

                hashPasswordBcrypt = Bcrypt.hash(password,Bcrypt_workFactor)

                ' or to use the default work factor:
                ' hashPasswordBcrypt = Bcrypt.hash(password)

                if use_pepper then

                    ' Alter the Bcrypt hash to indicate that the pepper was used.
                    ' This will be removed before verifying

                    hashPasswordBcrypt = replace(hashPasswordBcrypt,"$2a","$2a~P",1,-1,1)

                end if

            set Bcrypt = nothing

        end function

        public function hashPasswordPBKDF2(ByVal password)

            ' See https://github.com/as08/ClassicASP.PBKDF2 for installation instructions.

            Dim PBKDF2 : set PBKDF2 = server.CreateObject("ClassicASP.PBKDF2")

                ' Apply the pepper to the end of the password if specified.

                if use_pepper then password = password & pepper

                hashPasswordPBKDF2 =    "$PBKDF2$" & PBKDF2.hash(_
                                        password,_
                                        PBKDF2_iterations,_
                                        PBKDF2_alg,_
                                        PBKDF2_saltBytes,_
                                        PBKDF2_keyLength)

                ' or to use the default PBKDF2 parameters:
                ' hashPasswordPBKDF2 = "$PBKDF2$" & PBKDF2.hash(password)

                if use_pepper then

                    ' Alter the Bcrypt hash to indicate that the pepper was used.
                    ' This will be removed before verifying

                    hashPasswordPBKDF2 = replace(hashPasswordPBKDF2,"$PBKDF2","$PBKDF2~P",1,-1,1)

                end if

            set PBKDF2 = nothing

        end function

        public function verifyPassword(ByVal pass, ByVal theHash)
            
            ' Invalid by default

            verifyPassword = false
            
            ' Catch any unhandled errors returned by the COM DLL's.
            ' False will be returned in the event of an unhandled error
            
            on error resume next

            ' Was the hash generated using hashPasswordArgon2?

            if inStr(1,theHash,"$argon2i",1) = 1 then

                Dim agron2 : set agron2 = server.CreateObject("ClassicASP.Argon2")

                    ' apply the pepper?

                    if inStr(1,theHash,"$argon2i~P",1) = 1 then

                        pass = pass & pepper
                        theHash = replace(theHash,"$argon2i~P","$argon2i",1,-1,1)

                    end if

                    verifyPassword = agron2.verify(pass,theHash)

                set agron2 = nothing

            ' Was the hash generated using hashPasswordBcrypt?

            elseif inStr(1,theHash,"$2a",1) = 1 then

                Dim Bcrypt : set Bcrypt = server.CreateObject("ClassicASP.Bcrypt")

                    ' apply the pepper?

                    if inStr(1,theHash,"$2a~P",1) = 1 then

                        pass = pass & pepper
                        theHash = replace(theHash,"$2a~P","$2a",1,-1,1)

                    end if

                    verifyPassword = Bcrypt.verify(pass,theHash)

                set Bcrypt = nothing

            ' Was the hash generated using hashPasswordPBKDF2?

            elseif inStr(1,theHash,"$PBKDF2",1) = 1 then

                Dim PBKDF2 : set PBKDF2 = server.CreateObject("ClassicASP.PBKDF2")

                    ' apply the pepper?

                    if inStr(1,theHash,"$PBKDF2~P",1) = 1 then

                        pass = pass & pepper
                        theHash = replace(theHash,"~P","",1,-1,1)

                    end if

                    ' the $PBKDF2$ is just so the verifyPassword function can distinguish
                    ' PBKDF2 hashes, it's not needed by ClassicASP.PBKDF2

                    theHash = replace(theHash,"$PBKDF2$","",1,-1,1)

                    verifyPassword = PBKDF2.verify(pass,theHash)

                set PBKDF2 = nothing

            else

                ' A valid hash should be made up of 4 parts

                theHash = split(theHash,"$")

                if NOT uBound(theHash) = 4 then exit function

                ' Decode the salt

                Dim decoded_salt

                decoded_salt = decodeSalt(theHash(4),theHash(2))

                ' was the pepper used during the original hash? If so, apply during 
                ' the verification

                if inStr(theHash(1),"~P") > 0 then

                    ' apply the salt and pepper

                    pass = pepper & pass & decoded_salt

                    ' remove the "~P" from the algorithm name

                    theHash(1) = replace(theHash(1),"~P","")

                else

                    ' apply just the salt

                    pass = pass & decoded_salt

                end if

                ' verify the password

                ' check the returned key value against the value in the users 
                ' password hash

                if theHash(3) = _
                hash(pass,theHash(1),theHash(2)) _
                then verifyPassword = true

            end if
            
            ' reset any errors
            
            on error goto 0

        end function

        public function hash(ByVal input, ByVal alg, ByVal encoding)

            Dim hAlg, hEnc

            Set hAlg = CreateObject("System.Security.Cryptography." & get_hash_obj(alg))
            Set hEnc = CreateObject("System.Text.UTF8Encoding")

                hash = binaryEncode(hAlg.ComputeHash_2(hEnc.GetBytes_4(input)),encoding)     

            set hEnc = nothing
            set hAlg = nothing

        end function

        ' HMAC FUNCTIONS 

        ' To compute a HMAC using a secret key, call:
        ' hash_hmac("secret", "message", "hashing algorithm", "encoding")

        ' Hashing algorithms supported are MD5 / SHA1 / SHA256 / SHA384 / SHA512

        ' The encoding types are:
        ' hex = hexadecimal string
        ' b64/base64 = base64 string
        ' byteArray = byte array
        ' raw = raw binary

        ' response.write hash_hmac("the shared secret key here", "the message to hash here", "SHA256", "hex")

        ' EXPECTED: 4643978965ffcec6e6d73b36a39ae43ceb15f7ef8131b8307862ebc560e7f988
        ' RETURNED: 4643978965ffcec6e6d73b36a39ae43ceb15f7ef8131b8307862ebc560e7f988

        ' response.write hash_hmac("the shared secret key here", "the message to hash here", "SHA256", "b64")

        ' EXPECTED: RkOXiWX/zsbm1zs2o5rkPOsV9++BMbgweGLrxWDn+Yg=
        ' RETURNED: RkOXiWX/zsbm1zs2o5rkPOsV9++BMbgweGLrxWDn+Yg=

        public function hash_hmac(ByVal secret, ByVal message, ByVal alg, ByVal encoding)

            ' Convert the input to bytes if not already

            if NOT vartype(secret) = 8209 then secret = stringToUTFBytes(secret)
            if NOT vartype(message) = 8209 then message = stringToUTFBytes(message)

            Dim hAlg : Set hAlg = CreateObject("System.Security.Cryptography." & get_hmac_obj(alg))

                hAlg.Initialize() 
                hAlg.key = secret

                hash_hmac = binaryEncode(hAlg.ComputeHash_2((message)),encoding)             

           set hAlg = nothing

        end function

        private function binaryEncode(ByVal binary, ByVal encoding)

            Dim enc, pos

            ' convert the input to binary if not already

            if NOT varType(binary) = 8209 then binary = stringToBinary(binary)

            encoding = lCase(encoding)

            Set enc = CreateObject("MSXML2.DomDocument").CreateElement("encode")

                if encoding = "base64" OR encoding = "b64" then ' base64 string

                    enc.dataType = "bin.base64"
                    enc.nodeTypedValue = binary
                    binaryEncode = enc.Text 

                elseif encoding = "bytearray" then ' byte array

                    For pos = 1 To Lenb(binary)
                        binaryEncode = binaryEncode & Ascb(Midb(binary,pos,1))
                        if NOT pos = Lenb(binary) then binaryEncode = binaryEncode & ","
                    Next

                    binaryEncode = split(binaryEncode,",")

                elseif encoding = "raw" then ' raw binary

                    binaryEncode = binary

                else ' hexadecimal string

                    enc.dataType = "bin.hex"
                    enc.nodeTypedValue = binary
                    binaryEncode = enc.Text 

                end if

            Set enc = nothing

        end function

        private function get_hash_obj(ByVal alg)

            ' get the cryptography class name for the specified hashing algorithm,
            ' return the class name for SHA1 if not found

            select case uCase(alg)

                case "MD5"
                    get_hash_obj = "MD5CryptoServiceProvider"
                case "SHA1"
                    get_hash_obj = "SHA1CryptoServiceProvider"
                case "SHA2","SHA256"
                    get_hash_obj = "SHA256Managed"
                case "SHA3","SHA384"
                    get_hash_obj = "SHA384Managed"
                case "SHA5","SHA512"
                    get_hash_obj = "SHA512Managed"
                case else
                    get_hash_obj = "SHA1CryptoServiceProvider"

            end select

        end function

        private function get_hmac_obj(ByVal alg)

            ' get the cryptography class name for the specified HMAC algorithm,
            ' return the class name for SHA1 if not found

            select case uCase(alg)

                case "MD5"
                    get_hmac_obj = "HMACMD5"
                case "SHA1"
                    get_hmac_obj = "HMACSHA1"
                case "SHA3","SHA384"
                    get_hmac_obj = "HMACSHA384"
                case "SHA2","SHA256"
                    get_hmac_obj = "HMACSHA256"
                case "SHA5","SHA512"
                    get_hmac_obj = "HMACSHA512"
                case else
                    get_hmac_obj = "HMACSHA1"

            end select

        end function

        private function stringToUTFBytes(ByVal aString) 

            ' convert a UTF8 string to bytes

            Dim UTF8 : Set UTF8 = CreateObject("System.Text.UTF8Encoding") 
                stringToUTFBytes = UTF8.GetBytes_4(aString) 
            set UTF8 = nothing

        end function

        private function stringToBinary(ByVal aString) 

            ' convert a string to binary

            Dim BinaryStream
            Set BinaryStream = CreateObject("ADODB.Stream")

                BinaryStream.Type = 2
                BinaryStream.CharSet = "utf-8"
                BinaryStream.Open
                BinaryStream.WriteText aString
                BinaryStream.Position = 0
                BinaryStream.Type = 1
                BinaryStream.Position = 0
                stringToBinary = BinaryStream.Read

            Set BinaryStream = Nothing

        end function

        private function binaryToString(ByVal aBinary) 

            ' convert binary to a string

            Dim BinaryStream
            Set BinaryStream = CreateObject("ADODB.Stream")

                BinaryStream.Type = 1
                BinaryStream.Open
                BinaryStream.Write aBinary
                BinaryStream.Position = 0
                BinaryStream.Type = 2
                BinaryStream.CharSet = "utf-8"
                binaryToString = BinaryStream.ReadText

            Set BinaryStream = Nothing

        end function

        public function valid_password(ByVal password)

            ' At least one upper case English letter, (?=.*?[A-Z])
            ' At least one lower case English letter, (?=.*?[a-z])
            ' At least one digit, (?=.*?[0-9])
            ' At least one special character, (?=.*?[#?!@$%^&*-])
            ' Minimum 8 characters, maximum 72, .{8,72} (with the anchors)

            Dim vpRegExp : Set vpRegExp = New RegExp
            vpRegExp.Pattern = "^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-]).{8,72}$"
            valid_password = vpRegExp.Test(password)

        end function

        public function execution_time()

            ' call to see how long the class took to execute

            execution_time = formatNumber(Timer()-crypto_start,4)

        end function

    end class

%>
<script type="text/javascript" language="javascript" runat="server">

    /* 

        Salt generation functions for standard password hashing (Argon2, Bcrypt
        and PBKDF2 use System.Security.Cryptography.RandomNumberGenerator for
        generating salts. However this isn't available in VBscript without the
        use of a COM DLL. See https://github.com/as08/ClassicASP.PRNG if you 
        wish to generate stand-alone cryptographically secure pseudo-random 
        numbers and strings in VBscript).

        Javascript's Math.random() function produces a larger floating-point, 
        pseudo-random number compared to VBscript's Rnd() function, making it 
        a better choice for generating random salts

    */

    function randomBytes(bytes){

        for (var rndBytes = []; bytes > 0; bytes--) {
            rndBytes.push(Math.floor(Math.random() * 256));
        }
        for (var g = [], c = 0; c < rndBytes.length; c++) {
            g.push(String.fromCharCode(rndBytes[c]));
        }
        return g.join("");

    }

    function encodeSalt(bytes,encoding){

        for (var byteArray = [], c = 0; c < bytes.length; c++) {
            byteArray.push(bytes.charCodeAt(c) & 255);
        }

        encoding = encoding.toLowerCase();

        if (encoding == 'b64' || encoding == 'base64'){

            for (var b64 = [], c = 0; c < byteArray.length; c += 3) {
                for (var f = byteArray[c] << 16 | byteArray[c + 1] << 8 | byteArray[c + 2], g = 0; g < 4; g++) {
                    c * 8 + g * 6 <= byteArray.length * 8 ? b64.push("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".charAt(f >>> 6 * (3 - g) & 63)) : b64.push("=");
                }
            }
            return b64.join("");

        } else {

            for (var hex = [], c = 0; c < byteArray.length; c++) {
                hex.push((byteArray[c] >>> 4).toString(16)), hex.push((byteArray[c] & 15).toString(16));
            }
            return hex.join("");

        }

    }

    function decodeSalt(salt,encoding){

        encoding = encoding.toLowerCase();

        if (encoding == 'b64' || encoding == 'base64'){

            for (var salt = salt.replace(/[^A-Z0-9+\/]/ig, ""), h = [], c = 0, f = 0; c < salt.length; f = ++c % 4) {
                f != 0 && h.push(("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".indexOf(salt.charAt(c - 1)) & Math.pow(2, -2 * f + 8) - 1) << f * 2 | "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".indexOf(salt.charAt(c)) >>> 6 - f * 2);
            }
            for (var g = [], c = 0; c < h.length; c++) {
                g.push(String.fromCharCode(h[c]));
            }
            return g.join("");

        } else {

            for (var w = [], c = 0; c < salt.length; c += 2) {
                w.push(parseInt(salt.substr(c, 2), 16));
            }
            for (var g = [], c = 0; c < w.length; c++) {
                g.push(String.fromCharCode(w[c]));
            }
            return g.join("");

        }

    }

</script>
