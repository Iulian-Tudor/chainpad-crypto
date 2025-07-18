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

        // CryptoAgility abstraction of NaCl and other cryptographic operations
        var CryptoAgility = Crypto.CryptoAgility = {};

        CryptoAgility.decodeBase64 = decodeBase64;
        CryptoAgility.encodeBase64 = encodeBase64;

        CryptoAgility.decodeUTF8 = decodeUTF8;
        CryptoAgility.encodeUTF8 = encodeUTF8;

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
                return {
                    editKeyStr: keyStr,
                    signKey: encodeBase64(signKp.secretKey),
                    validateKey: encodeBase64(signKp.publicKey),
                    cryptKey: cryptKey,
                    viewKeyStr: b64Encode(cryptKey)
                };
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
                return {
                    cryptKey: decodeBase64(cryptKeyStr),
                    viewKeyStr: cryptKeyStr
                };
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

                return {
                    viewKeyStr: viewKeyStr,
                    cryptKey: cryptKey,
                    chanId: b64Encode(chanId),
                    secondarySignKey: encodeBase64(signKp2.secretKey),
                    secondaryValidateKey: encodeBase64(signKp2.publicKey),
                };
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
                return {
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
                return {
                    fileKeyStr: keyStr,
                    cryptKey: cryptKey,
                    chanId: b64Encode(chanId)
                };
            } catch (err) {
                console.error('[chainpad-crypto.createFileCryptor2] invalid string supplied');
                throw err;
            }
        };

        /*  Symmetric encryption used in CryptPad's one-to-one chat system
        */
        var Curve = Crypto.Curve = {};

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

        Curve.signAndEncrypt = function (msg, cryptKey, signKey) {
            var packed = Curve.encrypt(msg, cryptKey);
            return encodeBase64(Nacl.sign(decodeUTF8(packed), signKey));
        };

        Curve.openSigned = function (msg, cryptKey /*, validateKey STUBBED*/) {
            var content = decodeBase64(msg).subarray(64);
            return Curve.decrypt(encodeUTF8(content), cryptKey);
        };

        Curve.deriveKeys = function (theirs, mine) {
            try {
                var pub = decodeBase64(theirs);
                var secret = decodeBase64(mine);

                var sharedSecret = Nacl.box.before(pub, secret);
                var salt = decodeUTF8('CryptPad.signingKeyGenerationSalt');

                // 64 uint8s
                var hash = Nacl.hash(u8_concat([salt, sharedSecret]));
                var signKp = Nacl.sign.keyPair.fromSeed(hash.subarray(0, 32));
                var cryptKey = hash.subarray(32, 64);

                return {
                    cryptKey: encodeBase64(cryptKey),
                    signKey: encodeBase64(signKp.secretKey),
                    validateKey: encodeBase64(signKp.publicKey)
                };
            } catch (e) {
                console.error('invalid keys or other problem deriving keys');
                console.error(e);
                return null;
            }
        };

        Curve.createEncryptor = function (keys) {
            if (!keys || typeof(keys) !== 'object') {
                return void console.error("invalid input for createEncryptor");
            }

            var cryptKey = decodeBase64(keys.cryptKey);
            var signKey = decodeBase64(keys.signKey);
            var validateKey = decodeBase64(keys.validateKey);

            return {
                encrypt: function (msg) {
                    return Curve.signAndEncrypt(msg, cryptKey, signKey);
                },
                decrypt: function (packed) {
                    return Curve.openSigned(packed, cryptKey, validateKey);
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

        var u8_slice = function (A, start, end) {
            return new Uint8Array(Array.prototype.slice.call(A, start, end));
        };

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

                    console.log('[PQC] Using ML-KEM-512 for encryption');
                    console.log('[PQC] Encrypting with KEM key:', keys.their_kem_public);
                    console.log('[PQC] typeof:', typeof keys.their_kem_public, 'length:', keys.their_kem_public?.length);

                    const kemResult = Crypto.PQC.ml_kem.ml_kem512.encapsulate(
                        new Uint8Array(keys.their_kem_public) // ensure fresh copy
                    );
                    var kemSharedSecret = kemResult.sharedSecret;
                    var kemCiphertext = kemResult.ciphertext;

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
                    console.log('[PQC] Successfully added ML-KEM layer');
                } catch (e) {
                    console.warn('[PQC] Encryption failed, falling back to traditional:', e);
                    // Prepend with flag indicating no PQC
                    u8_bundle = u8_concat([new Uint8Array([0]), u8_bundle]);
                }
            } else {
                // No PQC available, prepend with flag
                u8_bundle = u8_concat([new Uint8Array([0]), u8_bundle]);
            }

            return u8_bundle;
        };

        // PQC-enhanced asymmetric decryption
        var pqc_asymmetric_decrypt = function (u8_bundle, keys) {
            // Check PQC flag
            var pqcFlag = u8_bundle[0];
            var payload = u8_slice(u8_bundle, 1);

            if (pqcFlag === 1 && keys.my_kem_private && Crypto.PQC && Crypto.PQC.ml_kem && Crypto.PQC.ml_kem.ml_kem512) {
                try {
                    console.log('[PQC] Detected ML-KEM layer, attempting decryption');
                    // Extract KEM ciphertext (1568 bytes for ML-KEM-512)
                    var kemCiphertext = u8_slice(payload, 0, 768);
                    var symNonce = u8_slice(payload, 768, 768 + Nacl.secretbox.nonceLength);
                    var symCipher = u8_slice(payload, 768 + Nacl.secretbox.nonceLength);

                    // Decrypt KEM to get shared secret
                    var kemSharedSecret = Crypto.PQC.ml_kem.ml_kem512.decapsulate(kemCiphertext, keys.my_kem_private);

                    // Recreate the traditional shared secret
                    var traditionalSharedSecret = Nacl.box.before(keys.their_public || keys.sender_public, keys.my_private);

                    // Derive the same symmetric key
                    var symmetricKey = deriveSymmetricKey(traditionalSharedSecret, kemSharedSecret);

                    // Decrypt the inner bundle
                    var innerBundle = Nacl.secretbox.open(symCipher, symNonce, symmetricKey);
                    if (!innerBundle) {
                        throw new Error('Failed to decrypt PQC layer');
                    }
                    console.log('[PQC] Successfully decrypted ML-KEM layer');

                    payload = innerBundle;
                } catch (e) {
                    console.error('[PQC] Decryption failed:', e);
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
                keys.their_public || u8_sender_public,
                keys.my_private
            );

            if (!u8_plain) { throw new Error('E_DECRYPTION_FAILURE'); }

            return {
                content: u8_plain,
                author: u8_sender_public,
            };
        };

        // PQC-enhanced message signing
        var pqc_sign_message = function (message, keys) {
            // Traditional NaCl signature
            var naclSig = Nacl.sign(message, keys.signingKey);

            // Add ML-DSA signature if available
            if (keys.dsaPrivate && Crypto.PQC && Crypto.PQC.ml_dsa && Crypto.PQC.ml_dsa.ml_dsa44) {
                try {
                    var mlDsaSig = Crypto.PQC.ml_dsa.ml_dsa44.sign(keys.dsaPrivate, message);
                    // Combine signatures: [naclSig][mlDsaSig]
                    return u8_concat([naclSig, mlDsaSig]);
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

                    // Verify ML-DSA signature
                    var mlDsaValid = Crypto.PQC.ml_dsa.ml_dsa44.verify(validateKeys.dsaPublic, originalMessage, mlDsaSig);
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
            var u8_ephemeral_kem_keypair = keys.ephemeral_kem_keypair || Crypto.PQC.ml_kem.ml_kem512.keygen();

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

        var encryptForTeam = function (plain, keys) {
            // sign(curve(curve(msg, author_curve), ephemeral_curve), signing_key)
            var u8_plain = decodeUTF8(plain);

            /* // DELIBERATE TEST FAILURE - Force PQC failure by corrupting the KEM public key if it exists
            if (keys.team_kem_public) {
                console.log('[PQC-TEST] Deliberately corrupting KEM public key to test error handling');
                // Make a copy and corrupt the first byte to cause a failure
                var originalKey = keys.team_kem_public;
                var corruptKey = new Uint8Array(originalKey.length);
                corruptKey.set(originalKey);
                if (corruptKey.length > 0) {
                    corruptKey[0] = (corruptKey[0] + 1) % 256; // Change first byte
                }
                keys.team_kem_public = corruptKey;
            }*/

            // Inner encryption layer with traditional NaCl and optional PQC
            console.log('[PQC] Encrypting with KEM key:', keys.their_kem_public);
            console.log('[PQC] typeof:', typeof keys.their_kem_public, 'length:', keys.their_kem_public?.length);
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
                    console.log('[PQC] Generating ephemeral ML-KEM keypair for team encryption');
                    u8_ephemeral_kem_keypair = Crypto.PQC.ml_kem.ml_kem512.keygen();
                } catch (err) {
                    console.error("[PQC] Failed to generate ephemeral KEM keypair:", err);
                }
            }

            // Outer encryption layer with traditional NaCl and optional PQC
            console.log('[PQC] Encrypting with KEM key:', keys.their_kem_public);
            console.log('[PQC] typeof:', typeof keys.their_kem_public, 'length:', keys.their_kem_public?.length);
            var u8_outer = pqc_asymmetric_encrypt(u8_inner, {
                their_public: keys.team_curve_public,
                their_kem_public: keys.team_kem_public,
                my_private: u8_ephemeral_keypair.secretKey,
                my_public: u8_ephemeral_keypair.publicKey,
                my_kem_private: u8_ephemeral_kem_keypair?.secretKey,
                my_kem_public: u8_ephemeral_kem_keypair?.publicKey,
            });


            // Sign the final message with classical NaCl signature or hybrid signature if PQC is available
            if (keys.team_dsa_private && Crypto.PQC && Crypto.PQC.ml_dsa && Crypto.PQC.ml_dsa.ml_dsa44) {
                try {
                    console.log('[PQC] Creating hybrid signature for team message (NaCl + ML-DSA)');
                    // Create classical signature
                    var classical_sig = Nacl.sign(u8_outer, keys.team_ed_private);

                    // Create post-quantum signature
                    var pq_sig = Crypto.PQC.ml_dsa.ml_dsa44.sign(keys.team_dsa_private, u8_outer);

                    // Combine both signatures into a hybrid signature format
                    // First the classical signature (contains message), then the PQ signature
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
                    var pqVerified = Crypto.PQC.ml_dsa.ml_dsa44.verify(keys.team_dsa_public, u8_outer, pqSig);
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
            // {content: u8, author: u8_curve_public (ephemeral) }
            var inner = pqc_asymmetric_decrypt(u8_outer, {
                my_private: keys.team_curve_private,
                my_kem_private: keys.team_kem_private,
                their_public: undefined, // not needed if sender is embedded
                sender_public: undefined
            });


            // Innermost decryption layer with PQC support
            // {content: u8, author: u8_curve_public }
            var u8_plain = pqc_asymmetric_decrypt(inner.content, {
                my_private: keys.team_curve_private,
                my_kem_private: keys.team_kem_private,
                their_public: inner.author,
                sender_public: inner.author
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

            myCurvePublic: 'my_curve_public', // encrypt (authorship inclusion)
            myCurvePrivate: 'my_curve_private', // encrypt (encryption)

            teamEdPublic: 'team_ed_public', // decrypt (validation)
            teamEdPrivate: 'team_ed_private', // encrypt (signing)
        };

        var team_can_decrypt = function (K /* u8_keys */) {
            return Boolean(
                // team_curve_private (to read messages encrypted for the team)
                K.team_curve_private && K.team_curve_private.length === Nacl.box.secretKeyLength &&
                // team_sign_public (to validate that messages are signed by team members)
                K.team_ed_public && K.team_ed_public.length === Nacl.sign.publicKeyLength
            );
        };

        var team_can_encrypt = function (K /* u8_keys */) {
            return Boolean(
                // my_curve_private (for the inner authenticated encryption)
                K.my_curve_private && K.my_curve_private.length === Nacl.box.secretKeyLength &&
                // my_curve_public (for inclusion in the inner message)
                K.my_curve_public && K.my_curve_public.length === Nacl.box.publicKeyLength &&
                // team_curve_public (to encrypt for the team)
                K.team_curve_public && K.team_curve_public.length === Nacl.box.publicKeyLength &&
                // team_ed_private (to sign the final message)
                K.team_ed_private && K.team_ed_private.length === Nacl.sign.secretKeyLength
            );
        };

        var team_validate_own_keys = function (K) {
            return Boolean(
                K.curvePublic && decodeBase64(K.curvePublic).length === Nacl.box.publicKeyLength &&
                K.curvePrivate && decodeBase64(K.curvePrivate).length === Nacl.box.secretKeyLength
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
                    teamKemPair = Crypto.PQC.ml_kem.ml_kem512.keygen(kemSeed);
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
            return u8_deriveGuestKeys(decodeBase64(Crypto.b64AddSlashes(seed2)));
        };

        Team.createSeed = function () {
            return Crypto.b64AddSlashes(encodeBase64(Nacl.randomBytes(18)));
        };

        Team.deriveMemberKeys = function (seed1, myKeys) {
            var u8_seed1;
            try {
                u8_seed1 = decodeBase64(Crypto.b64AddSlashes(seed1));
                if (u8_seed1.length < 18) { throw new Error("INVALID_SEED"); }
            } catch (err) {
                throw err;
            }

            // my_keys => {myCurvePublic, myCurvePrivate}
            if (!team_validate_own_keys(myKeys)) { throw new Error('INVALID_OWN_KEYS'); }

            var stretched = u8_stretch(u8_seed1);

            // team_ed_private, team_ed_public (distributed via historyKeeper)
            var teamEd = Nacl.sign.keyPair.fromSeed(stretched[0]);

            // Generate PQ signing keys if available
            var teamDsaPair = null;
            if (Crypto.PQC && Crypto.PQC.ml_dsa && Crypto.PQC.ml_dsa.ml_dsa44) {
                try {
                    var dsaSeed = Nacl.hash(u8_concat([stretched[0], u8_seed1])).subarray(0, 32);
                    teamDsaPair = Crypto.PQC.ml_dsa.ml_dsa44.internal.keygen(dsaSeed);
                } catch (err) {
                    console.error("Failed to generate post-quantum DSA keys for team:", err);
                    teamDsaPair = null;
                }
            }

            // channel, team_curve_private, team_curve_public
            var guestKeys = u8_deriveGuestKeys(stretched[1]);

            var result = merge({
                // your keys myCurvePublic, myCurvePrivate
                myCurvePublic: myKeys.curvePublic,
                myCurvePrivate: myKeys.curvePrivate,
                // member keys (teamEdPrivate, teamEdPublic)
                teamEdPrivate: encodeBase64(teamEd.secretKey),
                teamEdPublic: encodeBase64(teamEd.publicKey),
            }, guestKeys); // guest keys & info (channel, teamCurvePrivate, teamCurvePublic)

            // Add PQC DSA keys if available
            if (teamDsaPair) {
                result.teamDsaPrivate = encodeBase64(teamDsaPair.secretKey);
                result.teamDsaPublic = encodeBase64(teamDsaPair.publicKey);
            }

            return result;
        };

        // returns an object
        // any of: {encrypt}, {decrypt}, {encrypt, decrypt}
        // throws if it is impossible to correctly create either method
        // encrypt and decrypt take strings as input
        // both log and return null in the event of internal errors
        // decrypt can optionally skip validation if you trust the source of the message
        Team.createEncryptor = function (keys) {
            var u8_keys = {};
            // Process traditional keys
            Object.keys(team_key_map).forEach(function (k) {
                if (!keys[k]) { return; }
                try {
                    u8_keys[team_key_map[k]] = decodeBase64(keys[k]);
                } catch (err) {
                    console.log(k);
                    throw new Error('INVALID_KEY_SUPPLIED');
                }
            });

            // Add PQC keys if available
            if (keys.teamKemPrivate) {
                try {
                    u8_keys.team_kem_private = decodeBase64(keys.teamKemPrivate);
                } catch (err) {
                    console.warn('Invalid teamKemPrivate key supplied', err);
                }
            }
            if (keys.teamKemPublic) {
                try {
                    u8_keys.team_kem_public = decodeBase64(keys.teamKemPublic);
                } catch (err) {
                    console.warn('Invalid teamKemPublic key supplied', err);
                }
            }
            if (keys.teamDsaPrivate) {
                try {
                    u8_keys.team_dsa_private = decodeBase64(keys.teamDsaPrivate);
                } catch (err) {
                    console.warn('Invalid teamDsaPrivate key supplied', err);
                }
            }
            if (keys.teamDsaPublic) {
                try {
                    u8_keys.team_dsa_public = decodeBase64(keys.teamDsaPublic);
                } catch (err) {
                    console.warn('Invalid teamDsaPublic key supplied', err);
                }
            }

            var out = {};

            if (team_can_encrypt(u8_keys)) {
                // (utf8_string) => base64_string || null
                out.encrypt = function (plain) {
                    try {
                        return encryptForTeam(plain, u8_keys);
                    } catch (e) {
                        console.error(e);
                        return null;
                    }
                };
            }

            if (team_can_decrypt(u8_keys)) {
                // (base64_string, skip_validation_bool) => {content: utf8_string, author: base64_string} || null
                out.decrypt = function (cipher, skipValidation) {
                    try {
                        return decryptForTeam(cipher, u8_keys, skipValidation);
                    } catch (e) {
                        console.error(e);
                        return null;
                    }
                };
            }

            if (Object.keys(out).length === 0) { throw new Error("INVALID_TEAM_CONFIGURATION"); }

            return out;
        };

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
