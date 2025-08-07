(function () {
    'use strict';
    var factory = function (Nacl, NaclUtil, PostQuantum, Scrypt) {
        var Crypto = {
            Nacl: Nacl,
            PQC: PostQuantum
        };

        var encodeBase64 = NaclUtil.encodeBase64;
        var decodeBase64 = str => {
            let i;
            if (i = str.length % 4) { str += '='.repeat(4-i); }
            return NaclUtil.decodeBase64(str);
        };
        var decodeUTF8 = NaclUtil.decodeUTF8;
        var encodeUTF8 = NaclUtil.encodeUTF8;

        var encodeHex = function (bytes) {
            var hexString = '';
            for (var i = 0; i < bytes.length; i++) {
                if (bytes[i] < 16) { hexString += '0'; }
                hexString += bytes[i].toString(16);
            }
            return hexString;
        };
        /*
            var decodeHex = function (hexString) {
                var bytes = new Uint8Array(Math.ceil(hexString.length / 2));
                for (var i = 0; i < bytes.length; i++) {
                    bytes[i] = parseInt(hexString.substr(i * 2, 2), 16);
                }
                return bytes;
            };
        */

        // Post-quantum key derivation using scrypt
        var deriveSymmetricKey = function (naclKey, kemKey) {
            if (!naclKey || !kemKey) {
                throw new Error('Both NaCl and KEM keys required for key derivation');
            }

            var derived = new Uint8Array(32); // 32 bytes for the derived key

            Scrypt(
                Array.from(u8_concat([naclKey, kemKey])), // passwd
                Array.from(decodeUTF8('CryptPad.mailbox.pqc.salt')), // salt
                8, // N (CPU/memory cost parameter)
                1024,     // r (block size)
                128,    // dkLen
                200,   // interruptStep (default is 1k or 1000)
                function (result) {
                    for (var i = 0; i < result.length; i++) {
                        derived[i] = result[i];
                    }
                },
                'binary' // encoding
            );

            return derived;
        };

        // Utility function to concatenate Uint8Arrays
        var u8_concat = function (A) {
            // expect a list of uint8Arrays
            var length = 0;
            A.forEach(function (a) { length += a.length; });
            var total = new Uint8Array(length);

            var offset = 0;
            A.forEach(function (a) {
                total.set(a, offset);
                offset += a.length;
            });
            return total;
        };

        // Utility function to slice a Uint8Array
        var u8_slice = function (A, start, end) {
            return new Uint8Array(Array.prototype.slice.call(A, start, end));
        };

        // Reusable function to generate KEM keys with common error handling
        var generateKemKeypair = function(seed, errorContext) {
            if (!Crypto.PQC || !Crypto.PQC.ml_kem || !Crypto.PQC.ml_kem.ml_kem512) {
                return null;
            }

            try {
                // Ensure seed is exactly 64 bytes
                var kemSeed;
                if (!seed) {
                    kemSeed = Nacl.randomBytes(64);
                } else if (seed.length === 64) {
                    kemSeed = seed;
                } else {
                    // Hash the seed to get a deterministic 64-byte value
                    kemSeed = Nacl.hash(seed).subarray(0, 64);
                }

                var kemPair = Crypto.PQC.ml_kem.ml_kem512.keygen(kemSeed);
                return {
                    publicKey: kemPair.publicKey,
                    secretKey: kemPair.secretKey
                };
            } catch (err) {
                console.error('[chainpad-crypto.' + errorContext + '] failed to generate PQC KEM keys', err);
                return null;
            }
        };

        // Reusable function to generate DSA keys with common error handling
        var generateDsaKeypair = function(seed, errorContext) {
            if (!Crypto.PQC || !Crypto.PQC.ml_dsa || !Crypto.PQC.ml_dsa.ml_dsa44) {
                return null;
            }

            try {
                // Ensure seed is exactly 32 bytes
                var dsaSeed;
                if (!seed) {
                    dsaSeed = Nacl.randomBytes(32);
                } else if (seed.length === 32) {
                    dsaSeed = seed;
                } else {
                    // Hash the seed to get a deterministic 32-byte value
                    dsaSeed = Nacl.hash(seed).subarray(0, 32);
                }

                var dsaPair = Crypto.PQC.ml_dsa.ml_dsa44.internal.keygen(dsaSeed);
                return {
                    publicKey: dsaPair.publicKey,
                    secretKey: dsaPair.secretKey
                };
            } catch (err) {
                console.error('[chainpad-crypto.' + errorContext + '] failed to generate PQC DSA keys', err);
                return null;
            }
        };

        // Helper to add KEM keys to a result object
        var addKemKeysToResult = function(result, kemPair, publicKeyName, privateKeyName) {
            if (kemPair) {
                result[publicKeyName || 'kemPublic'] = encodeBase64(kemPair.publicKey);
                result[privateKeyName || 'kemPrivate'] = encodeBase64(kemPair.secretKey);
            }
            return result;
        };

        // Helper to add DSA keys to a result object
        var addDsaKeysToResult = function(result, dsaPair, publicKeyName, privateKeyName) {
            if (dsaPair) {
                result[publicKeyName || 'dsaPublic'] = encodeBase64(dsaPair.publicKey);
                result[privateKeyName || 'dsaPrivate'] = encodeBase64(dsaPair.secretKey);
            }
            return result;
        };

        // KEM operations
        var kemEncapsulate = function(publicKey, errorContext) {
            if (!Crypto.PQC || !Crypto.PQC.ml_kem || !Crypto.PQC.ml_kem.ml_kem512) {
                return null;
            }

            try {
                var kemPublicKey = publicKey;
                var result = Crypto.PQC.ml_kem.ml_kem512.encapsulate(kemPublicKey);
                return {
                    sharedSecret: result.sharedSecret,
                    cipherText: result.cipherText
                };
            } catch (err) {
                console.error('[chainpad-crypto.' + (errorContext || 'kemEncapsulate') + '] failed to encapsulate with KEM', err);
                return null;
            }
        };

        var kemDecapsulate = function(cipherText, privateKey, errorContext) {
            if (!Crypto.PQC || !Crypto.PQC.ml_kem || !Crypto.PQC.ml_kem.ml_kem512) {
                return null;
            }

            try {
                var kemCipherText = cipherText;
                var kemPrivateKey = privateKey;
                var sharedSecret = Crypto.PQC.ml_kem.ml_kem512.decapsulate(kemCipherText, kemPrivateKey);
                return sharedSecret;
            } catch (err) {
                console.error('[chainpad-crypto.' + (errorContext || 'kemDecapsulate') + '] failed to decapsulate KEM', err);
                return null;
            }
        };

        // DSA operations
        var dsaSign = function(privateKey, message, errorContext) {
            if (!Crypto.PQC || !Crypto.PQC.ml_dsa || !Crypto.PQC.ml_dsa.ml_dsa44) {
                return null;
            }

            try {
                var dsaMessage = message;
                var dsaPrivateKey = privateKey;

                return Crypto.PQC.ml_dsa.ml_dsa44.sign(dsaPrivateKey, dsaMessage);
            } catch (err) {
                console.error('[chainpad-crypto.' + (errorContext || 'dsaSign') + '] failed to sign with DSA', err);
                return null;
            }
        };

        var dsaVerify = function(publicKey, message, signature, errorContext) {
            if (!Crypto.PQC || !Crypto.PQC.ml_dsa || !Crypto.PQC.ml_dsa.ml_dsa44) {
                return false;
            }

            try {
                var dsaPublicKey = publicKey;
                var dsaMessage = message;
                var dsaSignature = signature;

                return Crypto.PQC.ml_dsa.ml_dsa44.verify(dsaPublicKey, dsaMessage, dsaSignature);
            } catch (err) {
                console.error('[chainpad-crypto.' + (errorContext || 'dsaVerify') + '] failed to verify DSA signature', err);
                return false;
            }
        };

        // CryptoAgility abstraction of NaCl and other cryptographic operations
        var CryptoAgility = Crypto.CryptoAgility = {};

        CryptoAgility.decodeBase64 = decodeBase64;
        CryptoAgility.encodeBase64 = encodeBase64;

        CryptoAgility.decodeUTF8 = decodeUTF8;
        CryptoAgility.encodeUTF8 = encodeUTF8;

        CryptoAgility.generateKemKeypair = generateKemKeypair;
        CryptoAgility.generateDsaKeypair = generateDsaKeypair;
        CryptoAgility.addKemKeysToResult = addKemKeysToResult;
        CryptoAgility.addDsaKeysToResult = addDsaKeysToResult;

        CryptoAgility.kemDecapsulate = kemDecapsulate;
        CryptoAgility.kemEncapsulate = kemEncapsulate;
        CryptoAgility.dsaSign = dsaSign;
        CryptoAgility.dsaVerify = dsaVerify;


        CryptoAgility.signKeyPairFromSeed = function(seed) {
            return Nacl.sign.keyPair.fromSeed(seed);
        };

        CryptoAgility.signKeyPairFromSecretKey = function(secretKey) {
            return Nacl.sign.keyPair.fromSecretKey(secretKey);
        };

        CryptoAgility.signKeyPair = function() {
            return Nacl.sign.keyPair();
        };

        CryptoAgility.sign = function(message, secretKey) {
            return Nacl.sign(message, secretKey);
        }

        CryptoAgility.signOpen = function(signedMessage, publicKey) {
            return Nacl.sign.open(signedMessage, publicKey);
        }

        CryptoAgility.signDetached = function(message, secretKey) {
            return Nacl.sign.detached(message, secretKey);
        }

        CryptoAgility.verifyDetached = function(signature, message, publicKey) {
            return Nacl.sign.detached.verify(message, signature, publicKey);
        }

        CryptoAgility.curveKeyPair = function() {
            return Nacl.box.keyPair();
        };

        CryptoAgility.box = function(message, nonce, theirPublicKey, mySecretKey) {
            return Nacl.box(message, nonce, theirPublicKey, mySecretKey);
        };

        CryptoAgility.boxOpen = function(ciphertext, nonce, theirPublicKey, mySecretKey) {
            return Nacl.box.open(ciphertext, nonce, theirPublicKey, mySecretKey);
        }

        CryptoAgility.boxKeyPairFromSecretKey = function(secretKey) {
            return Nacl.box.keyPair.fromSecretKey(secretKey);
        };

        CryptoAgility.secretbox = function(message, nonce, key) {
            return Nacl.secretbox(message, nonce, key);
        }

        CryptoAgility.secretboxOpen = function(ciphertext, nonce, key) {
            return Nacl.secretbox.open(ciphertext, nonce, key);
        };

        CryptoAgility.createHash = function(data) {
            return Nacl.hash(data);
        };

        CryptoAgility.bytes = function(length) {
            return Nacl.randomBytes(length);
        };

        CryptoAgility.boxNonceLength = function() {
            return Nacl.box.nonceLength;
        }

        CryptoAgility.signSeedLength = function() {
            return Nacl.sign.seedLength;
        }

        CryptoAgility.boxKeyLength = function() {
            return Nacl.box.publicKeyLength;
        }

        CryptoAgility.secretboxKeyLength = function() {
            return Nacl.secretbox.keyLength;
        }

        CryptoAgility.secretboxNonceLength = function() {
            return Nacl.secretbox.nonceLength;
        }

        CryptoAgility.signKeyLength = function() {
            return Nacl.sign.publicKeyLength;
        }


        // Box encryption and decryption abstraction
        var Box = Crypto.Box = {};

        // Box encryption
        Box.encrypt = function(message, nonce, theirPublicKey, mySecretKey) {
            return Nacl.box(message, nonce, theirPublicKey, mySecretKey);
        };

        // Box decryption
        Box.decrypt = function(ciphertext, nonce, theirPublicKey, mySecretKey) {
            return Nacl.box.open(ciphertext, nonce, theirPublicKey, mySecretKey);
        };

        // Box.after encryption
        Box.encryptAfter = function(message, nonce, sharedSecret) {
            return Nacl.box.after(message, nonce, sharedSecret);
        };

        // Box.after decryption
        Box.decryptAfter = function(ciphertext, nonce, sharedSecret) {
            return Nacl.box.open.after(ciphertext, nonce, sharedSecret);
        };

        // Box shared secret creation
        Box.getSharedSecret = function(theirPublicKey, mySecretKey) {
            return Nacl.box.before(theirPublicKey, mySecretKey);
        };

        // SecretBox (symmetric) encryption/decryption abstraction
        var SecretBox = Crypto.SecretBox = {};

        // SecretBox encryption
        SecretBox.encrypt = function(message, nonce, key) {
            return Nacl.secretbox(message, nonce, key);
        };

        // SecretBox decryption
        SecretBox.decrypt = function(ciphertext, nonce, key) {
            return Nacl.secretbox.open(ciphertext, nonce, key);
        };

        // Signature abstraction
        var Sign = Crypto.Sign = {};

        // Sign a message
        Sign.sign = function(message, secretKey) {
            return Nacl.sign(message, secretKey);
        };

        // Verify a signature
        Sign.verify = function(signedMessage, publicKey) {
            return Nacl.sign.open(signedMessage, publicKey);
        };

        // Detached sign
        Sign.detached = function(message, secretKey) {
            return Nacl.sign.detached(message, secretKey);
        };

        // Verify detached
        Sign.verifyDetached = function(signature, message, publicKey) {
            return Nacl.sign.detached.verify(message, signature, publicKey);
        };


        var encryptStr = function (str, key) {
            var array = decodeUTF8(str);
            var nonce = CryptoAgility.bytes(24);
            var packed = SecretBox.encrypt(array, nonce, key);
            if (!packed) { throw new Error(); }
            return encodeBase64(nonce) + "|" + encodeBase64(packed);
        };

        var decryptStr = function (str, key) {
            var arr = str.split('|');
            if (arr.length !== 2) { throw new Error(); }
            var nonce = decodeBase64(arr[0]);
            var packed = decodeBase64(arr[1]);
            var unpacked = SecretBox.decrypt(packed, nonce, key);
            if (!unpacked) { throw new Error(); }
            return encodeUTF8(unpacked);
        };

        var encrypt = Crypto.encrypt = function (msg, key) {
            return encryptStr(msg, key);
        };

        var decrypt = Crypto.decrypt = function (msg, key) {
            return decryptStr(msg, key);
        };

        var parseKey = Crypto.parseKey = function (str) {
            try {
                var array = decodeBase64(str);
                var hash = CryptoAgility.createHash(array);
                var lk = hash.subarray(32);
                return {
                    lookupKey: lk,
                    cryptKey: hash.subarray(0,32),
                    channel: encodeBase64(lk).substring(0,10)
                };
            } catch (err) {
                console.error('[chainpad-crypto.parseKey] invalid string supplied');
                throw err;
            }
        };

        var rand64 = Crypto.rand64 = function (bytes) {
            return encodeBase64(CryptoAgility.bytes(bytes));
        };

        Crypto.genKey = function () {
            return rand64(18);
        };

        var b64Encode = function (bytes) {
            return encodeBase64(bytes).replace(/\//g, '-').replace(/=+$/g, '');
        };

        var b64Decode = function (str) {
            return decodeBase64(str.replace(/\-/g, '/'));
        };

        Crypto.b64RemoveSlashes = function (str) {
            return str.replace(/\//g, '-');
        };

        Crypto.b64AddSlashes = function (str) {
            return str.replace(/\-/g, '/');
        };

        /*

    * several modes of operation:
      * if input is not an object, use some prehistoric code
      * otherwise
        * get the encryption key
        * get the signing key, if available
        * MAYBE get a validateKey
      * return a pair of functions: {encrypt, decrypt} which "Do The Right Thing"
        * encrypt is not necessarily provided, depending on the parameters with which the encryptor was initialized
        */
        Crypto.createEncryptor = function (input) {
            var key;
            if (typeof input === 'object') {
                var out = {};
                key = input.cryptKey;
                if (!key) { throw new Error("NO_DECRYPTION_KEY_PROVIDED"); }

                if (input.signKey) {
                    var signKey = decodeBase64(input.signKey);
                    out.encrypt = function (msg) {
                        return encodeBase64(Nacl.sign(decodeUTF8(encrypt(msg, key)), signKey));
                    };
                }

                out.decrypt = function (msg, validateKey, skipCheck) {
                    if (!validateKey && !skipCheck) {
                        throw new Error("UNSUPPORTED_DECRYPTION_CONFIGURATION");
                        //return decrypt(msg, key);
                    }

                    if (validateKey === true && !skipCheck) {
                        console.error("UNEXPECTED_CONFIGURATION");
                    }

                    // .subarray(64) remove the signature since it's taking lots of time and it's already checked server-side.
                    // We only need to check when the message is not coming from history keeper
                    var validated = (skipCheck || typeof validateKey !== "string")
                        ? decodeBase64(msg).subarray(64)
                        : Nacl.sign.open(decodeBase64(msg), decodeBase64(validateKey));
                    if (!validated) { return; }
                    return decrypt(encodeUTF8(validated), key);
                };
                return out;
            }
            key = parseKey(input).cryptKey;
            return {
                encrypt: function (msg) {
                    return encrypt(msg, key);
                },
                decrypt: function (msg) {
                    return decrypt(msg, key);
                }
            };
        };

        Crypto.createEditCryptor = function (keyStr, seed) {
            try {
                if (!keyStr) {
                    if (seed && seed.length !== 18) {
                        throw new Error('expected supplied seed to have length of 18');
                    }
                    else if (!seed) { seed = Nacl.randomBytes(18); }
                    keyStr = encodeBase64(seed);
                }
                var hash = Nacl.hash(decodeBase64(keyStr));
                var signKp = Nacl.sign.keyPair.fromSeed(hash.subarray(0, 32));
                var cryptKey = hash.subarray(32, 64);
                var result = {
                    editKeyStr: keyStr,
                    signKey: encodeBase64(signKp.secretKey),
                    validateKey: encodeBase64(signKp.publicKey),
                    cryptKey: cryptKey,
                    viewKeyStr: b64Encode(cryptKey)
                };

                // Add PQC keys if available
                var kemPair = generateKemKeypair(hash, 'createEditCryptor');
                result = addKemKeysToResult(result, kemPair);

                var dsaPair = generateDsaKeypair(signKp.secretKey, 'createEditCryptor');
                result = addDsaKeysToResult(result, dsaPair);

                return result;
            } catch (err) {
                console.error('[chainpad-crypto.createEditCryptor] invalid string supplied');
                throw err;
            }
        };

        Crypto.createViewCryptor = function (cryptKeyStr) {
            try {
                if (!cryptKeyStr) {
                    throw new Error("Cannot open a new pad in read-only mode!");
                }

                var cryptKey = decodeBase64(cryptKeyStr);
                var result = {
                    cryptKey: cryptKey,
                    viewKeyStr: cryptKeyStr
                };

                // Add PQC keys if available
                var kemPair = generateKemKeypair(cryptKey, 'createViewCryptor');
                result = addKemKeysToResult(result, kemPair);

                return result;
            } catch (err) {
                console.error('[chainpad-crypto.createViewCryptor] invalid string supplied');
                throw err;
            }
        };

        var createViewCryptor2 = Crypto.createViewCryptor2 = function (viewKeyStr, password) {
            try {
                if (!viewKeyStr) {
                    throw new Error("Cannot open a new pad in read-only mode!");
                }
                var seed = b64Decode(viewKeyStr);
                var superSeed = seed;
                if (password) {
                    var pwKey = decodeUTF8(password);
                    superSeed = new Uint8Array(seed.length + pwKey.length);
                    superSeed.set(pwKey);
                    superSeed.set(seed, pwKey.length);
                }
                var hash = Nacl.hash(superSeed);
                var chanId = hash.subarray(0,16);
                var cryptKey = hash.subarray(16, 48);

                // Under certain circumstances we want people who have view access to also have
                // a signing capability. This is the case of forms where participants can't
                // edit the schema (chainpad) but can push messages via another channel and need to sign
                // them.
                // This secondary signing key should be derivable from the classic view seed and
                // we can always build a version 1 hash that doesn't contain this informaton.
                var signKp2 = Nacl.sign.keyPair.fromSeed(hash.subarray(32, 64));

                var result = {
                    viewKeyStr: viewKeyStr,
                    cryptKey: cryptKey,
                    chanId: b64Encode(chanId),
                    secondarySignKey: encodeBase64(signKp2.secretKey),
                    secondaryValidateKey: encodeBase64(signKp2.publicKey),
                };

                // Generate PQC keys if available
                var kemPair = generateKemKeypair(u8_concat([hash, superSeed]), 'createViewCryptor2');
                result = addKemKeysToResult(result, kemPair);

                // Generate PQC signature keys if available
                var dsaPair = generateDsaKeypair(u8_concat([hash.subarray(32, 64), superSeed]), 'createViewCryptor2');
                result = addDsaKeysToResult(result, dsaPair);

                return result;
            } catch (err) {
                console.error('[chainpad-crypto.createViewCryptor2] invalid string supplied');
                throw err;
            }
        };

        Crypto.createEditCryptor2 = function (keyStr, seed, password) {
            try {
                if (!keyStr) {
                    if (seed && seed.length !== 18) {
                        throw new Error('expected supplied seed to have length of 18');
                    }
                    else if (!seed) { seed = Nacl.randomBytes(18); }
                    keyStr = b64Encode(seed);
                }
                if (!seed) {
                    seed = b64Decode(keyStr);
                }
                var superSeed = seed;
                if (password) {
                    var pwKey = decodeUTF8(password);
                    superSeed = new Uint8Array(seed.length + pwKey.length);
                    superSeed.set(pwKey);
                    superSeed.set(seed, pwKey.length);
                }
                var hash = Nacl.hash(superSeed);
                var signKp = Nacl.sign.keyPair.fromSeed(hash.subarray(0, 32));
                // under certain circumstances we want people who have edit access to also have
                // a secondary capability conferred by a symmetric key.
                // This secondary key should be derivable from the classic view hash,
                // but also delegated individually without leaking any information about the editing secrets
                // hashing the secretKey component of the signing keypair accomplishes this
                var secondary = Nacl.hash(signKp.secretKey).subarray(0, Nacl.secretbox.keyLength);

                var seed2 = hash.subarray(32, 64);
                var viewKeyStr = b64Encode(seed2);
                var viewCryptor = createViewCryptor2(viewKeyStr, password);

                var result = {
                    editKeyStr: keyStr,
                    viewKeyStr: viewKeyStr,
                    signKey: encodeBase64(signKp.secretKey),
                    validateKey: encodeBase64(signKp.publicKey),
                    cryptKey: viewCryptor.cryptKey,
                    secondaryKey: encodeBase64(secondary),
                    chanId: viewCryptor.chanId,
                    secondarySignKey: viewCryptor.secondarySignKey,
                    secondaryValidateKey: viewCryptor.secondaryValidateKey
                };

                // Include PQC keys from viewCryptor
                if (viewCryptor.kemPublic) {
                    result.kemPublic = viewCryptor.kemPublic;
                    result.kemPrivate = viewCryptor.kemPrivate;
                }

                if (viewCryptor.secondaryDsaKey) {
                    result.secondaryDsaKey = viewCryptor.secondaryDsaKey;
                    result.secondaryDsaValidateKey = viewCryptor.secondaryDsaValidateKey;
                }

                // Generate primary PQC DSA keys if available
                var dsaPair = generateDsaKeypair(hash.subarray(0, 32), 'createEditCryptor2');
                result = addDsaKeysToResult(result, dsaPair);

                return result;
            } catch (err) {
                console.error('[chainpad-crypto.createEditCryptor2] invalid string supplied');
                throw err;
            }
        };

        Crypto.createFileCryptor2 = function (keyStr, password) {
            try {
                var seed;
                if (!keyStr) {
                    seed = Nacl.randomBytes(18);
                    keyStr = b64Encode(seed);
                }
                if (!seed) {
                    seed = b64Decode(keyStr);
                }
                var superSeed = seed;
                if (password) {
                    var pwKey = decodeUTF8(password);
                    superSeed = new Uint8Array(seed.length + pwKey.length);
                    superSeed.set(pwKey);
                    superSeed.set(seed, pwKey.length);
                }
                var hash = Nacl.hash(superSeed);
                var chanId = hash.subarray(0,24);
                var cryptKey = hash.subarray(24, 56);

                var result = {
                    fileKeyStr: keyStr,
                    cryptKey: cryptKey,
                    chanId: b64Encode(chanId)
                };

                // Add PQC keys if available
                var kemPair = generateKemKeypair(u8_concat([hash, superSeed]), 'createFileCryptor2');
                result = addKemKeysToResult(result, kemPair);

                // Add PQC signature keys if needed
                var dsaPair = generateDsaKeypair(u8_concat([hash.subarray(56, 64), superSeed]), 'createFileCryptor2');
                result = addDsaKeysToResult(result, dsaPair);

                return result;
            } catch (err) {
                console.error('[chainpad-crypto.createFileCryptor2] invalid string supplied');
                throw err;
            }
        };

        /*  Symmetric encryption used in CryptPad's one-to-one chat system
        */
        var Curve = Crypto.Curve = {};

        Curve.encrypt = function (message, secret) {
            var buffer = decodeUTF8(message);
            var nonce = Nacl.randomBytes(24);
            var box = Nacl.box.after(buffer, nonce, secret);
            return encodeBase64(nonce) + '|' + encodeBase64(box);
        };

        Curve.decrypt = function (packed, secret) {
            var unpacked = packed.split('|');
            var nonce = decodeBase64(unpacked[0]);
            var box = decodeBase64(unpacked[1]);
            var message = Nacl.box.open.after(box, nonce, secret);
            if (!message) { return null; }
            return encodeUTF8(message);
        };

        Curve.signAndEncrypt = function (msg, cryptKey, signKey, dsaPrivate) {
            var packed = Curve.encrypt(msg, cryptKey);
            var signedMessage = decodeUTF8(packed);

            // Generate hybrid signature if PQC is available
            if (dsaPrivate && Crypto.PQC && Crypto.PQC.ml_dsa && Crypto.PQC.ml_dsa.ml_dsa44) {
                try {
                    // Generate classical signature (always required)
                    var classicalSig = Nacl.sign(signedMessage, signKey);

                    // Generate post-quantum signature
                    var mlDsaSig = dsaSign(dsaPrivate, signedMessage);

                    // Combine signatures: [classicalSig][mlDsaSig]
                    var hybridSig = u8_concat([classicalSig, mlDsaSig]);
                    return encodeBase64(hybridSig);
                } catch (e) {
                    console.warn('ML-DSA signing failed, using only NaCl:', e);
                }
            }

            // Classical signature only
            return encodeBase64(Nacl.sign(signedMessage, signKey));
        };

        Curve.openSigned = function (msg, cryptKey, validateKey, dsaPublic) {
            var signedMessage = decodeBase64(msg);

            // Check if we have both signatures
            var naclSigLength = 64;
            var mlDsaSigLength = 2420; // ML-DSA-44 signature length

            if (signedMessage.length >= naclSigLength + mlDsaSigLength &&
                dsaPublic &&
                Crypto.PQC && Crypto.PQC.ml_dsa && Crypto.PQC.ml_dsa.ml_dsa44) {

                try {
                    // Extract both signatures
                    var naclPortion = u8_slice(signedMessage, 0, naclSigLength + signedMessage.length - naclSigLength - mlDsaSigLength);
                    var mlDsaSig = u8_slice(signedMessage, signedMessage.length - mlDsaSigLength);
                    var originalMessage = u8_slice(signedMessage, naclSigLength, signedMessage.length - mlDsaSigLength);

                    // Verify NaCl signature
                    var naclResult = Nacl.sign.open(naclPortion, validateKey);
                    if (!naclResult) {
                        return null;
                    }

                    // Verify ML-DSA signature
                    var mlDsaValid = dsaVerify(dsaPublic, originalMessage, mlDsaSig);
                    if (!mlDsaValid) {
                        return null;
                    }

                    return Curve.decrypt(encodeUTF8(originalMessage), cryptKey);
                } catch (e) {
                    console.error('PQC signature verification failed:', e);
                    return null;
                }
            }

            // Fall back to traditional NaCl verification
            var content = signedMessage.subarray(64);
            return Curve.decrypt(encodeUTF8(content), cryptKey);
        };


        Curve.deriveKeys = function (theirs, mine, theirsKem, mineKem) {
            try {
                const pub = decodeBase64(theirs);
                const secret = decodeBase64(mine);
                const theirKemPub = decodeBase64(theirsKem);

                const sharedSecret = Nacl.box.before(pub, secret);

                if (theirKemPub.length !== 800) {
                    throw new Error("Invalid KEM public key length: expected 800 bytes");
                }

                const kemResult = kemEncapsulate(theirKemPub);
                const kemSharedSecret = kemResult.sharedSecret;


                const symmetricKey = deriveSymmetricKey(sharedSecret, kemSharedSecret);


                const salt = decodeUTF8('CryptPad.signingKeyGenerationSalt');
                const hash = Nacl.hash(u8_concat([salt, symmetricKey])); // 64B

                const signKp = Nacl.sign.keyPair.fromSeed(hash.subarray(0, 32));
                const cryptKey = hash.subarray(32, 64); // 32B

                const result = {
                    cryptKey: encodeBase64(cryptKey),
                    signKey: encodeBase64(signKp.secretKey),
                    validateKey: encodeBase64(signKp.publicKey),
                };

                if (Crypto.PQC?.ml_dsa?.ml_dsa44) {
                    try {
                        const pqcSalt = decodeUTF8('CryptPad.curve.pqcSalt');
                        const pqcSeed = Nacl.hash(u8_concat([symmetricKey, pqcSalt])).subarray(0, 32);
                        const dsaPair = generateDsaKeypair(pqcSeed);

                        result.dsaPrivate = encodeBase64(dsaPair.secretKey);
                        result.dsaPublic = encodeBase64(dsaPair.publicKey);
                    } catch (err) {
                        console.error("Failed to generate PQC signature keys:", err);
                    }
                }

                return result;

            } catch (e) {
                console.error("Failed to derive keys:", e);
                return null;
            }
        };

        Curve.createEncryptor = function (keys) {
            if (!keys || typeof(keys) !== 'object') {
                console.error("invalid input for createEncryptor");
                return {
                    encrypt: function () { throw new Error("Invalid encryptor: keys missing or malformed"); },
                    decrypt: function () { throw new Error("Invalid encryptor: keys missing or malformed"); }
                };
            }

            var cryptKey, signKey, validateKey;
            var dsaPrivate, dsaPublic;

            try {
                cryptKey = decodeBase64(keys.cryptKey);
                signKey = decodeBase64(keys.signKey);
                validateKey = decodeBase64(keys.validateKey);

                // PQC keys (optional)
                dsaPrivate = keys.dsaPrivate ? decodeBase64(keys.dsaPrivate) : undefined;
                dsaPublic = keys.dsaPublic ? decodeBase64(keys.dsaPublic) : undefined;
            } catch (e) {
                console.error("Failed to decode keys for createEncryptor:", e);
                return {
                    encrypt: function () { throw new Error("Invalid encryptor: failed to decode keys"); },
                    decrypt: function () { throw new Error("Invalid encryptor: failed to decode keys"); }
                };
            }

            return {
                encrypt: function (msg) {
                    return Curve.signAndEncrypt(msg, cryptKey, signKey, dsaPrivate);
                },
                decrypt: function (packed) {
                    return Curve.openSigned(packed, cryptKey, validateKey, dsaPublic);
                }
            };
        };

        /*  Mailbox encryption

        Assuming an API for appending messages to a public append-only log...
        Define an encryption scheme which:
        1. protects the plaintexts of appended messages from all but their authors and the holder of an asymmetric keypair
        2. optionally proves authorship of the message to the recipient
        3. guarantees unlinkability of appended ciphertexts in the absence of the private key

        Accomplish this by:
        1. encrypting a message with the recipient's public key and your own private key
        2. encrypting the resulting ciphertext with an ephemeral key

        Use-cases...
        1. leave a message for a friend
        2. publish a post to a private mailing list
        3. submit private data to a public form
        4. cast an authenticated vote in public
        5. use the public log as a mixnet, leaving messages for undisclosed recipients

        */


        var Mailbox = Crypto.Mailbox = {};

        // PQC-enhanced asymmetric encryption
        var pqc_asymmetric_encrypt = function (u8_plain, keys) {
            // First, do traditional NaCl encryption
            var u8_nonce = Nacl.randomBytes(Nacl.box.nonceLength);
            var u8_cipher = Nacl.box(
                u8_plain,
                u8_nonce,
                keys.their_public,
                keys.my_private
            );

            var u8_bundle = u8_concat([
                u8_nonce,
                keys.my_public,
                u8_cipher,
            ]);

            // If PQC keys are available, add another layer of encryption
            if (keys.their_kem_public && Crypto.PQC && Crypto.PQC.ml_kem && Crypto.PQC.ml_kem.ml_kem512) {
                try {
                    const kemResult = kemEncapsulate(keys.their_kem_public, 'pqc_asymmetric_encrypt');

                    if (!kemResult || !kemResult.sharedSecret || !kemResult.cipherText) {
                        throw new Error('[PQC] Encapsulate failed: result is undefined or incomplete');
                    }
                    var kemSharedSecret = kemResult.sharedSecret;
                    var kemCiphertext = kemResult.cipherText;

                    if (!kemSharedSecret || kemSharedSecret.length !== 32) {
                        throw new Error('[PQC] Internal encapsulate failed to return sharedSecret');
                    }

                    // Derive symmetric key from traditional shared secret and KEM shared secret
                    var traditionalSharedSecret = Nacl.box.before(keys.their_public, keys.my_private);
                    var symmetricKey = deriveSymmetricKey(traditionalSharedSecret, kemSharedSecret);

                    // Encrypt the bundle with the derived symmetric key
                    var symNonce = Nacl.randomBytes(Nacl.secretbox.nonceLength);
                    var symCipher = Nacl.secretbox(u8_bundle, symNonce, symmetricKey);

                    // Bundle with KEM ciphertext
                    u8_bundle = u8_concat([
                        new Uint8Array([1]), // PQC flag
                        kemCiphertext,
                        symNonce,
                        symCipher
                    ]);
                } catch (e) {
                    console.warn('[PQC] Encryption failed, falling back to traditional:', e);
                    // Prepend with flag indicating no PQC
                    u8_bundle = u8_concat([new Uint8Array([0]), u8_bundle]);
                }
            } else {
                // No PQC available, prepend with flag
                u8_bundle = u8_concat([new Uint8Array([0]), u8_bundle]);
            }

            var result = new Uint8Array(u8_bundle);
            result.content = result;               // optional for clarity
            result.author = keys.my_public;
            result.author_kem = keys.my_kem_public;
            return result;
        };

        // PQC-enhanced asymmetric decryption
        var pqc_asymmetric_decrypt = function (u8_bundle, keys) {
            // Check PQC flag
            var pqcFlag = u8_bundle[0];
            var payload = u8_slice(u8_bundle, 1);

            if (pqcFlag === 1 && keys.my_kem_private && Crypto.PQC && Crypto.PQC.ml_kem && Crypto.PQC.ml_kem.ml_kem512) {
                try {
                    // Extract KEM ciphertext (768 bytes for ML-KEM-512)
                    var kemCiphertext = u8_slice(payload, 0, 768);
                    var symNonce = u8_slice(payload, 768, 768 + Nacl.secretbox.nonceLength);
                    var symCipher = u8_slice(payload, 768 + Nacl.secretbox.nonceLength);

                    var kemSharedSecret = kemDecapsulate(kemCiphertext, keys.my_kem_private, 'pqc_asymmetric_decrypt');

                    // Recreate the traditional shared secret
                    var traditionalSharedSecret = Nacl.box.before(keys.their_public, keys.my_private);

                    // Derive the same symmetric key
                    var symmetricKey = deriveSymmetricKey(traditionalSharedSecret, kemSharedSecret);

                    // Decrypt the inner bundle
                    var innerBundle = Nacl.secretbox.open(symCipher, symNonce, symmetricKey);
                    if (!innerBundle) {
                        throw new Error('Failed to decrypt PQC layer');
                    }
                    payload = innerBundle;
                } catch (e) {
                    throw new Error('E_PQC_DECRYPTION_FAILURE');
                }
            }

            // Now decrypt the traditional NaCl layer
            var u8_nonce = u8_slice(payload, 0, Nacl.box.nonceLength);
            var u8_sender_public = u8_slice(
                payload,
                Nacl.box.nonceLength,
                Nacl.box.nonceLength + Nacl.box.publicKeyLength
            );
            var u8_cipher = u8_slice(
                payload,
                Nacl.box.nonceLength + Nacl.box.publicKeyLength
            );

            var u8_plain = Nacl.box.open(
                u8_cipher,
                u8_nonce,
                u8_sender_public,
                keys.my_private
            );

            if (!u8_plain) { throw new Error('E_DECRYPTION_FAILURE'); }

            var result = new Uint8Array(u8_plain);
            result.content = result;                  // optional, for clarity
            result.author = u8_sender_public;         // Curve25519 public key
            result.author_kem = keys.my_kem_public;   // ML-KEM public key (not needed for decryption, but useful for validation)
            return result;

        };

        // PQC-enhanced message signing
        var pqc_sign_message = function (message, keys) {
            // Traditional NaCl signature
            var naclSig = Nacl.sign(message, keys.signingKey);

            // Add ML-DSA signature if available
            if (keys.dsaPrivate && Crypto.PQC && Crypto.PQC.ml_dsa && Crypto.PQC.ml_dsa.ml_dsa44) {
                try {
                    var mlDsaSig = dsaSign(keys.dsaPrivate, message, 'pqc_sign_message');
                    if (mlDsaSig) {
                        // Combine signatures: [naclSig][mlDsaSig]
                        return u8_concat([naclSig, mlDsaSig]);
                    }
                } catch (e) {
                    console.warn('ML-DSA signing failed, using only NaCl:', e);
                }
            }

            return naclSig;
        };

        // PQC-enhanced signature verification
        var pqc_verify_signature = function (signedMessage, validateKeys) {
            // Check if we have both signatures
            var naclSigLength = 64;
            var mlDsaSigLength = 2420; // ML-DSA-44 signature length

            if (signedMessage.length >= naclSigLength + mlDsaSigLength &&
                validateKeys.dsaPublic &&
                Crypto.PQC && Crypto.PQC.ml_dsa && Crypto.PQC.ml_dsa.ml_dsa44) {

                try {
                    // Extract both signatures
                    var naclPortion = u8_slice(signedMessage, 0, naclSigLength + signedMessage.length - naclSigLength - mlDsaSigLength);
                    var mlDsaSig = u8_slice(signedMessage, signedMessage.length - mlDsaSigLength);
                    var originalMessage = u8_slice(signedMessage, naclSigLength, signedMessage.length - mlDsaSigLength);

                    // Verify NaCl signature
                    var naclResult = Nacl.sign.open(naclPortion, validateKeys.validateKey);
                    if (!naclResult) {
                        return null;
                    }

                    var mlDsaValid = dsaVerify(validateKeys.dsaPublic, originalMessage, mlDsaSig, 'pqc_verify_signature');
                    if (!mlDsaValid) {
                        return null;
                    }

                    return originalMessage;
                } catch (e) {
                    console.error('PQC signature verification failed:', e);
                    return null;
                }
            }

            // Fall back to traditional NaCl verification
            return Nacl.sign.open(signedMessage, validateKeys.validateKey);
        };

        // basically acts like an envelope marked only with a delivery address
        var sealSecretLetter = Mailbox.sealSecretLetter = function (plain, keys) {
            // decode string into u8
            var u8_plain = decodeUTF8(plain);

            // encrypt with your permanent private key and the mailbox's public key
            var u8_letter = pqc_asymmetric_encrypt(u8_plain, {
                their_public: keys.their_public,
                their_kem_public: keys.their_kem_public,
                my_private: keys.my_private,
                my_public: keys.my_public,
                my_kem_private: keys.my_kem_private,
                my_kem_public: keys.my_kem_public
            });

            // generate an ephemeral keypair or use the provided one
            var u8_ephemeral_keypair = keys.ephemeral_keypair || Nacl.box.keyPair();
            var u8_ephemeral_kem_keypair = keys.ephemeral_kem_keypair || generateKemKeypair();

            // seal with an ephemeral key
            var u8_sealed = pqc_asymmetric_encrypt(u8_letter, {
                their_public: keys.their_public,
                their_kem_public: keys.their_kem_public,
                my_private: u8_ephemeral_keypair.secretKey,
                my_public: u8_ephemeral_keypair.publicKey,
                my_kem_private: u8_ephemeral_kem_keypair.secretKey,
                my_kem_public: u8_ephemeral_kem_keypair.publicKey,
            });


            // if we have signing keys, also sign the message with PQC
            if (keys.signingKey) {
                u8_sealed = pqc_sign_message(u8_sealed, {
                    signingKey: keys.signingKey,
                    dsaPrivate: keys.dsaPrivate
                });
            }

            // return the doubly-encrypted 'envelope' as a base64-encoded string
            return encodeBase64(u8_sealed);
        };

        Mailbox.openOwnSecretLetter = function (b64_bundle, keys) {
            // transform the b64 ciphertext into a Uint8Array
            var u8_bundle = decodeBase64(b64_bundle);

            // If the message is signed, verify and remove the signature
            if (keys.validateKey) {
                u8_bundle = pqc_verify_signature(u8_bundle, {
                    validateKey: keys.validateKey,
                    dsaPublic: keys.dsaPublic
                });
                if (!u8_bundle) {
                    throw new Error('E_SIGNATURE_VERIFICATION_FAILED');
                }
            }

            // open the sealed envelope with your ephemeral private key
            var letter = pqc_asymmetric_decrypt(u8_bundle, {
                my_private: keys.ephemeral_private,
                my_kem_private: keys.ephemeral_kem_private,
                their_public: keys.their_public,
            });

            // read the internal content, remember its author
            var u8_plain = pqc_asymmetric_decrypt(letter.content, {
                my_private: keys.my_private,
                my_kem_private: keys.my_kem_private,
                their_public: keys.their_public
            });

            // return the content and author
            return {
                content: encodeUTF8(u8_plain.content),
                author: encodeBase64(u8_plain.author),
            };
        };

        var openSecretLetter = Mailbox.openSecretLetter = function (b64_bundle, keys) {
            // transform the b64 ciphertext into a Uint8Array
            var u8_bundle = decodeBase64(b64_bundle);

            // If the message is signed, verify and remove the signature
            if (keys.validateKey) {
                u8_bundle = pqc_verify_signature(u8_bundle, {
                    validateKey: keys.validateKey,
                    dsaPublic: keys.dsaPublic
                });
                if (!u8_bundle) {
                    throw new Error('E_SIGNATURE_VERIFICATION_FAILED');
                }
            }

            // open the sealed envelope with your private key
            var letter = pqc_asymmetric_decrypt(u8_bundle, {
                my_private: keys.my_private,
                my_kem_private: keys.my_kem_private,
                their_public: keys.their_public
            });

            // read the internal content, remember its author
            var u8_plain = pqc_asymmetric_decrypt(letter.content, {
                my_private: keys.my_private,
                my_kem_private: keys.my_kem_private,
                their_public: keys.their_public
            });

            // return the content and author
            return {
                content: encodeUTF8(u8_plain.content),
                author: encodeBase64(u8_plain.author),
            };
        };

        Mailbox.createEncryptor = function (keys) {
            // validate inputs
            if (!keys || typeof(keys) !== 'object') {
                return void console.error("invalid Mailbox.createEncryptor keys");
            }

            ['curvePublic', 'curvePrivate'].forEach(function (k) {
                if (typeof(keys[k]) !== 'string') {
                    console.log(k);
                    throw new Error("Expected key was not present");
                }
            });

            var u8_my_private = decodeBase64(keys.curvePrivate);
            var u8_my_public = decodeBase64(keys.curvePublic);

            // PQC keys (optional)
            var u8_my_kem_private = keys.kemPrivate ? decodeBase64(keys.kemPrivate) : undefined;
            var u8_my_kem_public = keys.kemPublic ? decodeBase64(keys.kemPublic) : undefined;

            var signingKey = keys.signingKey ? decodeBase64(keys.signingKey) : undefined;
            var validateKey = keys.validateKey ? decodeBase64(keys.validateKey) : undefined;
            var dsaPrivate = keys.dsaPrivate ? decodeBase64(keys.dsaPrivate) : undefined;
            var dsaPublic = keys.dsaPublic ? decodeBase64(keys.dsaPublic) : undefined;

            return  {
                // returns a base-64 encoded ciphertext bundle
                // or null if decryption failed
                encrypt: function (plain, recipient, recipientKem) {
                    // decode the recipient's keys
                    var u8_their_public = decodeBase64(recipient);
                    var u8_their_kem_public = recipientKem ? decodeBase64(recipientKem) : undefined;

                    // prepare an unmarked envelope for them
                    try {
                        var sealed = sealSecretLetter(plain, {
                            signingKey: signingKey,
                            dsaPrivate: dsaPrivate,
                            ephemeral_keypair: keys.ephemeral_keypair,
                            ephemeral_kem_keypair: keys.ephemeral_kem_keypair,

                            their_public: u8_their_public,
                            their_kem_public: u8_their_kem_public,

                            my_private: u8_my_private,
                            my_kem_private: u8_my_kem_private,
                            my_public: u8_my_public,
                            my_kem_public: u8_my_kem_public,
                        });
                        return sealed;
                    } catch (e) {
                        console.error(e);
                        return null;
                    }
                },
                // return an object with content and author
                // or null if decryption failed
                decrypt: function (cipher) {
                    try {
                        return openSecretLetter(cipher, {
                            validateKey: validateKey,
                            dsaPublic: dsaPublic,
                            my_private: u8_my_private,
                            my_kem_private: u8_my_kem_private,
                        });
                    } catch (e) {
                        console.error(e);
                        return null;
                    }
                },
            };
        };

        /*  Team encryption

        Much like mailbox encryption but intended for use cases where:
        1. a private signing key is required to write messages to a shared log
        2. a private decryption key is required to read messages
        3. authorship can be authenticated by those with the private decryption key
        4. authorship is unlinkable to anyone without the decryption key

        We assume:
        1. The private signing key will be distribute to privileged members of a group
        2. The private decryption key can be distributed to anyone who should be able to read messages
        3. It is safe for anyone to have the public encryption key
        4. We may want to allow either:
            * write capabilities without read capabilities
            * read capabilities without write capabilities
        5. The public validation key will be transmitted out of band to anyone who needs it

        */

        var Team = Crypto.Team = {};

        function getRawUint8Array(obj) {
            return (obj instanceof Uint8Array)
                ? obj
                : obj.u8_bundle || obj.content || new Uint8Array(obj);
        }

        var encryptForTeam = function (plain, keys) {
            // sign(curve(curve(msg, author_curve), ephemeral_curve), signing_key)
            var u8_plain = decodeUTF8(plain);

            // Inner encryption layer with traditional NaCl and optional PQC
            var u8_inner = pqc_asymmetric_encrypt(u8_plain, {
                their_public: keys.team_curve_public,
                their_kem_public: keys.team_kem_public,
                my_private: keys.my_curve_private,
                my_public: keys.my_curve_public,
                my_kem_private: keys.my_kem_private,
                my_kem_public: keys.my_kem_public
            });


            // Generate ephemeral keypair for the outer encryption layer
            var u8_ephemeral_keypair = Nacl.box.keyPair();

            // Generate ephemeral KEM keypair for PQC if available
            var u8_ephemeral_kem_keypair = null;
            if (Crypto.PQC && Crypto.PQC.ml_kem && Crypto.PQC.ml_kem.ml_kem512) {
                try {
                    u8_ephemeral_kem_keypair = generateKemKeypair();
                } catch (err) {
                    console.error("[PQC] Failed to generate ephemeral KEM keypair:", err);
                }
            }

            // Outer encryption layer with traditional NaCl and optional PQC
            var u8_outer = pqc_asymmetric_encrypt(u8_inner, {
                their_public: keys.team_curve_public,
                their_kem_public: keys.team_kem_public,
                my_private: u8_ephemeral_keypair.secretKey,
                my_public: u8_ephemeral_keypair.publicKey,
                my_kem_private: u8_ephemeral_kem_keypair?.secretKey,
                my_kem_public: u8_ephemeral_kem_keypair?.publicKey,
            });

            // Embed ephemeral KEM public key into author
            if (u8_ephemeral_kem_keypair?.publicKey && typeof u8_outer === 'object' && u8_outer.author instanceof Uint8Array) {
                u8_outer = {
                    content: u8_outer.content,
                    author: u8_outer.author,
                    author_kem: u8_ephemeral_kem_keypair.publicKey
                };
            }


            // Sign the final message with classical NaCl signature or hybrid signature if PQC is available
            if (keys.team_dsa_private && Crypto.PQC && Crypto.PQC.ml_dsa && Crypto.PQC.ml_dsa.ml_dsa44) {
                try {
                    // using raw Uint8Array for signing due to bundling
                    const raw = getRawUint8Array(u8_outer);
                    const classical_sig = Nacl.sign(raw, keys.team_ed_private);
                    const pq_sig = dsaSign(keys.team_dsa_private, raw);
                    return encodeBase64(u8_concat([classical_sig, pq_sig]));
                } catch (err) {
                    console.error("[PQC] Failed to create hybrid team signature, falling back to classical:", err);
                    // Fall back to classical signature
                    return encodeBase64(Nacl.sign(u8_outer, keys.team_ed_private));
                }
            }

            // Classical signature only
            return encodeBase64(Nacl.sign(u8_outer, keys.team_ed_private));
        };


        // INTERNAL USE ONLY
        // throws on decryption or validation errors
        var decryptForTeam = function (b64_bundle, keys, skipValidation) {
            var u8_bundle = decodeBase64(b64_bundle);

            var u8_outer;
            // Check if we have a hybrid signature with both classical and quantum signatures
            var naclSigLength = 64;
            var mlDsaSigLength = 2420; // ML-DSA-44 signature length
            var hasHybridSignature = u8_bundle.length > naclSigLength + mlDsaSigLength &&
                keys.team_dsa_public &&
                Crypto.PQC && Crypto.PQC.ml_dsa && Crypto.PQC.ml_dsa.ml_dsa44;

            if (skipValidation === true) {
                u8_outer = u8_slice(u8_bundle, 64);
            } else if (hasHybridSignature) {
                try {
                    // Extract classical signature portion (which contains the signed message)
                    var classicalSigPortion = u8_slice(u8_bundle, 0, u8_bundle.length - mlDsaSigLength);
                    // Extract the message from the classical signature
                    u8_outer = Nacl.sign.open(classicalSigPortion, keys.team_ed_public);
                    if (!u8_outer) {
                        throw new Error("Classical signature verification failed");
                    }

                    // Now verify the PQ signature
                    var pqSig = u8_slice(u8_bundle, u8_bundle.length - mlDsaSigLength);
                    var pqVerified = dsaVerify(keys.team_dsa_public, u8_outer, pqSig);
                    if (!pqVerified) {
                        throw new Error("Post-quantum signature verification failed");
                    }
                } catch (e) {
                    console.error("Hybrid signature verification failed:", e);
                    // Try classical verification as fallback
                    u8_outer = Nacl.sign.open(u8_bundle, keys.team_ed_public);
                    if (u8_outer === null) { throw new Error("E_VALIDATION_FAILURE"); }
                }
            } else {
                // Standard classical verification
                u8_outer = Nacl.sign.open(u8_bundle, keys.team_ed_public);
                if (u8_outer === null) { throw new Error("E_VALIDATION_FAILURE"); }
            }

            // Inner decryption layer with PQC support
            var inner = pqc_asymmetric_decrypt(u8_outer, {
                my_private: keys.team_curve_private,
                my_kem_private: keys.team_kem_private,
                their_public: keys.team_curve_public,
                sender_public: keys.team_kem_public,
            });

            // Innermost decryption layer with PQC support
            var u8_plain = pqc_asymmetric_decrypt(inner.content, {
                my_private: keys.team_curve_private,
                my_kem_private: keys.team_kem_private,
                their_public: inner.author,
                sender_public: inner.author_kem,
            });

            return {
                content: encodeUTF8(u8_plain.content),
                author: encodeBase64(u8_plain.author),
            };
        };

        // external names => internal names
        var team_key_map = {
            teamCurvePublic: 'team_curve_public', // encrypt (to encrypt for)
            teamCurvePrivate: 'team_curve_private', // decrypt (decryption)

            teamKemPrivate: 'team_kem_private', // decrypt (optional PQC decryption)
            teamKemPublic: 'team_kem_public', // encrypt (optional PQC)

            myCurvePublic: 'my_curve_public', // encrypt (authorship inclusion)
            myCurvePrivate: 'my_curve_private', // encrypt (encryption)

            myKemPublic: 'my_kem_public', // encrypt (optional PQC)
            myKemPrivate: 'my_kem_private', // encrypt (optional PQC)

            teamEdPublic: 'team_ed_public', // decrypt (validation)
            teamEdPrivate: 'team_ed_private', // encrypt (signing)

            teamDsaPublic: 'team_dsa_public', // decrypt (validation)
            teamDsaPrivate: 'team_dsa_private', // encrypt (signing)
        };

        var team_can_decrypt = function (K /* u8_keys */) {
            return Boolean(
                // Traditional Curve key
                K.team_curve_private && K.team_curve_private.length === Nacl.box.secretKeyLength &&

                // PQC: Optional but recommended for hybrid mode
                (!Crypto.PQC || !Crypto.PQC.ml_kem || !Crypto.PQC.ml_kem.ml_kem512 ||
                    (K.team_kem_private && K.team_kem_private.length === 1632)) &&

                // Public team signing key
                K.team_ed_public && K.team_ed_public.length === Nacl.sign.publicKeyLength
            );
        };


        var team_can_encrypt = function (K /* u8_keys */) {
            return Boolean(
                // Traditional keys
                K.my_curve_private && K.my_curve_private.length === Nacl.box.secretKeyLength &&
                K.my_curve_public  && K.my_curve_public.length === Nacl.box.publicKeyLength &&
                K.team_curve_public && K.team_curve_public.length === Nacl.box.publicKeyLength &&

                // PQC: Optional but recommended for hybrid mode
                (!Crypto.PQC || !Crypto.PQC.ml_kem || !Crypto.PQC.ml_kem.ml_kem512 ||
                    (K.my_kem_private && K.my_kem_private.length === 1632 &&
                        K.my_kem_public  && K.my_kem_public.length === 800 &&
                        K.team_kem_public && K.team_kem_public.length === 800)) &&

                // Required to sign the outer message
                K.team_ed_private && K.team_ed_private.length === Nacl.sign.secretKeyLength &&

                // Optional PQC signer (hybrid signature)
                (!Crypto.PQC || !Crypto.PQC.ml_dsa || !Crypto.PQC.ml_dsa.ml_dsa44 ||
                    (K.team_dsa_private && K.team_dsa_private.length === 2560))
            );
        };


        var team_validate_own_keys = function (K) {
            return Boolean(
                K.curvePublic && decodeBase64(K.curvePublic).length === Nacl.box.publicKeyLength &&
                K.curvePrivate && decodeBase64(K.curvePrivate).length === Nacl.box.secretKeyLength &&

                // PQC support for UI validation / self-check (optional)
                (!K.kemPublic || decodeBase64(K.kemPublic).length === 800) &&
                (!K.kemPrivate || decodeBase64(K.kemPrivate).length === 1632)
            );
        };


        var u8_stretch = function (u8) {
            var hashed = Nacl.hash(u8);
            return [
                u8_slice(hashed, 0, 32),
                u8_slice(hashed, 32)
            ];
        };

        var merge = function (o1, o2) {
            var o3 = JSON.parse(JSON.stringify(o1));
            Object.keys(o2).forEach(function (k) {
                o3[k] = o2[k];
            });
            return o3;
        };

        var u8_deriveGuestKeys = function (u8_seed2) {
            // channel, team_curve_private, team_curve_public
            var stretched = u8_stretch(u8_seed2);

            var teamCurve = Nacl.box.keyPair.fromSecretKey(stretched[0]);
            var u8_channel = u8_slice(stretched[1], 0, 16);

            // Generate PQC KEM keys if available
            var teamKemPair = null;
            if (Crypto.PQC && Crypto.PQC.ml_kem && Crypto.PQC.ml_kem.ml_kem512) {
                try {
                    var kemSeed = Nacl.hash(u8_concat([stretched[0], u8_seed2]));
                    teamKemPair = generateKemKeypair(kemSeed);
                } catch (err) {
                    console.error("Failed to generate post-quantum KEM keys for team:", err);
                    teamKemPair = null;
                }
            }

            var result = {
                channel: encodeHex(u8_channel),
                teamCurvePublic: encodeBase64(teamCurve.publicKey),
                teamCurvePrivate: encodeBase64(teamCurve.secretKey),
                viewKeyStr: Crypto.b64RemoveSlashes(encodeBase64(u8_seed2)),
            };

            // Add PQC keys if available
            if (teamKemPair) {
                result.teamKemPublic = encodeBase64(teamKemPair.publicKey);
                result.teamKemPrivate = encodeBase64(teamKemPair.secretKey);
            }

            return result;
        };

        Team.deriveGuestKeys = function (seed2) {
            var start = (performance?.now?.() || Date.now());
            var result = u8_deriveGuestKeys(decodeBase64(Crypto.b64AddSlashes(seed2)));
            addTeamTime(start, 'Team.deriveGuestKeys');
            return result;
        };

        Team.createSeed = function () {
            var start = (performance?.now?.() || Date.now());
            var result = Crypto.b64AddSlashes(encodeBase64(Nacl.randomBytes(18)));
            addTeamTime(start, 'Team.createSeed');
            return result;
        };

        Team.deriveMemberKeys = function (seed1, myKeys) {
            var start = (performance?.now?.() || Date.now());
            var u8_seed1;
            try {
                u8_seed1 = decodeBase64(Crypto.b64AddSlashes(seed1));
                if (u8_seed1.length < 18) { throw new Error("INVALID_SEED"); }
            } catch (err) {
                throw err;
            }
            if (!team_validate_own_keys(myKeys)) { throw new Error('INVALID_OWN_KEYS'); }
            var stretched = u8_stretch(u8_seed1);
            var teamEd = Nacl.sign.keyPair.fromSeed(stretched[0]);
            var teamDsaPair = null;
            if (Crypto.PQC && Crypto.PQC.ml_dsa && Crypto.PQC.ml_dsa.ml_dsa44) {
                try {
                    var dsaSeed = Nacl.hash(u8_concat([stretched[0], u8_seed1])).subarray(0, 32);
                    teamDsaPair = generateDsaKeypair(dsaSeed);
                } catch (err) {
                    console.error("Failed to generate post-quantum DSA keys for team:", err);
                    teamDsaPair = null;
                }
            }
            var guestKeys = u8_deriveGuestKeys(stretched[1]);
            var result = merge({
                myCurvePublic: myKeys.curvePublic,
                myCurvePrivate: myKeys.curvePrivate,
                teamEdPrivate: encodeBase64(teamEd.secretKey),
                teamEdPublic: encodeBase64(teamEd.publicKey),
                myKemPublic: myKeys.kemPublic,
                myKemPrivate: myKeys.kemPrivate,
                teamDsaPrivate: encodeBase64(teamDsaPair?.secretKey),
                teamDsaPublic: encodeBase64(teamDsaPair?.publicKey),
            }, guestKeys);
            addTeamTime(start, 'Team.deriveMemberKeys');
            return result;
        };

        Team.createEncryptor = function (keys) {
            var start = (performance?.now?.() || Date.now());
            var u8_keys = {};
            Object.keys(team_key_map).forEach(function (k) {
                if (!keys[k]) { return; }
                try {
                    u8_keys[team_key_map[k]] = decodeBase64(keys[k]);
                } catch (err) {
                    console.log(k);
                    throw new Error('INVALID_KEY_SUPPLIED');
                }
            });
            var out = {};
            if (team_can_encrypt(u8_keys)) {
                out.encrypt = function (plain) {
                    var opStart = (performance?.now?.() || Date.now());
                    try {
                        var res = encryptForTeam(plain, u8_keys);
                        addTeamTime(opStart, 'Team.createEncryptor.encrypt');
                        return res;
                    } catch (e) {
                        console.error(e);
                        addTeamTime(opStart, 'Team.createEncryptor.encrypt');
                        return null;
                    }
                };
            }
            if (team_can_decrypt(u8_keys)) {
                out.decrypt = function (cipher, skipValidation) {
                    var opStart = (performance?.now?.() || Date.now());
                    try {
                        var res = decryptForTeam(cipher, u8_keys, skipValidation);
                        addTeamTime(opStart, 'Team.createEncryptor.decrypt');
                        return res;
                    } catch (e) {
                        console.error(e);
                        addTeamTime(opStart, 'Team.createEncryptor.decrypt');
                        return null;
                    }
                };
            }
            if (Object.keys(out).length === 0) { throw new Error("INVALID_TEAM_CONFIGURATION"); }
            addTeamTime(start, 'Team.createEncryptor');
            return out;
        };

        // --- Team operation timing ---
        var teamOperationTimes = [];
        var teamCumulativeTimeMs = 0;
        function addTeamTime(start, fnName) {
            const now = (performance?.now?.() || Date.now());
            const deltaMs = now - start;
            teamCumulativeTimeMs += deltaMs;
            teamOperationTimes.push({ fnName, deltaMs });
            const deltaSec = (deltaMs / 1000).toFixed(4);
            const totalSec = (teamCumulativeTimeMs / 1000).toFixed(4);
            console.log(`[Team timing] ${fnName}: +${deltaSec}s, cumulative: ${totalSec}s`);
            console.log('[Team timing] Operation times:', teamOperationTimes);
        };
        // --- End Team operation timing ---

        return Crypto;
    };

    if (typeof(module) !== 'undefined' && module.exports) {
        module.exports = factory(require('tweetnacl/nacl-fast'), require('tweetnacl-util'), require('./pqc-node'), require('scrypt-async'));
    } else if ((typeof(define) !== 'undefined' && define !== null) && (define.amd !== null)) {
        define([
            '/components/tweetnacl/nacl-fast.min.js',
            '/components/tweetnacl-util/nacl-util.min.js',
            '/components/@noble/post-quantum/index.js',
            '/components/scrypt-async/scrypt-async.min.js',
        ], function () {
            return factory(window.nacl, window.nacl?.util, window.PostQuantum, window.scrypt);
        });
    } else {
        window.chainpad_crypto = factory(window.nacl, window.PostQuantum, window.scrypt);
    }
}());

