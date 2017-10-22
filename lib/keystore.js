var CryptoJS = require('crypto-js');
var EC = require('elliptic').ec;
var ec = new EC('secp256k1');
var bitcore = require('bitcore-lib');
var Random = bitcore.crypto.Random;
var Hash = bitcore.crypto.Hash;
var Mnemonic = require('bitcore-mnemonic-en');
var nacl = require('tweetnacl');
var scrypt = require('scrypt-async');

var defaultSalt = 'lightwalletSalt'
var defaultHdPathString = "m/0'/0'/0'";

function strip0x (input) {
  if (typeof(input) !== 'string') {
    return input;
  }
  else if (input.length >= 2 && input.slice(0,2) === '0x') {
    return input.slice(2);
  }
  else {
    return input;
  }
}

function add0x (input) {
  if (typeof(input) !== 'string') {
    return input;
  }
  else if (input.length < 2 || input.slice(0,2) !== '0x') {
    return '0x' + input;
  }
  else {
    return input;
  }
}

function leftPadString (stringToPad, padChar, length) {

  var repreatedPadChar = '';
  for (var i=0; i<length; i++) {
    repreatedPadChar += padChar;
  }

  return ( (repreatedPadChar + stringToPad).slice(-length) );
}

function nacl_encodeHex(msgUInt8Arr) {
  var msgBase64 = nacl.util.encodeBase64(msgUInt8Arr);
  return (new Buffer(msgBase64, 'base64')).toString('hex');
}

function nacl_decodeHex(msgHex) {
  var msgBase64 = (new Buffer(msgHex, 'hex')).toString('base64');
  return nacl.util.decodeBase64(msgBase64);
}

var KeyStore = function(mnemonic, pwDerivedKey, hdPathString) {

  if (hdPathString === undefined) {
    hdPathString = defaultHdPathString;
  }
  this.defaultHdPathString = hdPathString;

  this.init(mnemonic, pwDerivedKey, hdPathString, defaultSalt);
};

KeyStore.prototype.init = function(mnemonic, pwDerivedKey, hdPathString, salt) {
  this.salt = salt
  this.ksData = {};
  this.ksData[hdPathString] = {};
  var pathKsData = this.ksData[hdPathString];
  pathKsData.info = {curve: 'secp256k1', purpose: 'sign'};

  this.encSeed = undefined;
  this.encHdRootPriv = undefined;
  this.version = 2;

  pathKsData.encHdPathPriv = undefined;
  pathKsData.hdIndex = 0;
  pathKsData.encPrivKeys = {};
  pathKsData.addresses = [];

  if ( (typeof pwDerivedKey !== 'undefined') && (typeof mnemonic !== 'undefined') ){
    var words = mnemonic.split(' ');
    if (!Mnemonic.isValid(mnemonic, Mnemonic.Words.ENGLISH) || words.length !== 12){
      throw new Error('KeyStore: Invalid mnemonic');
    }

    // Pad the seed to length 120 before encrypting
    var paddedSeed = leftPadString(mnemonic, ' ', 120);
    this.encSeed = encryptString(paddedSeed, pwDerivedKey);

    // hdRoot is the relative root from which we derive the keys using
    // generateNewAddress(). The derived keys are then
    // `hdRoot/hdIndex`.
    //
    // Default hdRoot is m/0'/0'/0', the overall logic is
    // m/0'/Persona'/Purpose', where the 0' purpose is
    // for standard Ethereum accounts.

    var hdRoot = new Mnemonic(mnemonic).toHDPrivateKey().xprivkey;
    this.encHdRootPriv = encryptString(hdRoot, pwDerivedKey);

    var hdRootKey = new bitcore.HDPrivateKey(hdRoot);
    var hdPath = hdRootKey.derive(hdPathString).xprivkey;
    pathKsData.encHdPathPriv = encryptString(hdPath, pwDerivedKey);
  }
}

KeyStore.createVault = function(opts, cb) {
  var _this = this;

  // Default hdPathString
  if (!('hdPathString' in opts)) {
    opts.hdPathString = "m/0'/0'/0'";
  }

  // Default seed phrase if not specified
  if (!('seedPhrase' in opts)) {
    opts.seedPhrase = this.generateRandomSeed();
  }

  if (!('salt' in opts)) {
    opts.salt = generateSalt(32);
  }

  this.deriveKeyFromPassword(opts.password, opts.salt, function(err, pwDerivedKey) {
    if (err) return cb(err);

    newMode = true
    var ks = new _this(opts.seedPhrase, pwDerivedKey, opts.hdPathString);
    newMode = false

    ks.init(opts.seedPhrase, pwDerivedKey, opts.hdPathString, opts.salt);

    cb(null, ks);
  });
};

KeyStore.generateSalt = generateSalt;

function generateSalt (byteCount) {
  return bitcore.crypto.Random.getRandomBuffer(byteCount || 32).toString('base64');
}

function encryptString (string, pwDerivedKey) {
  var nonce = nacl.randomBytes(nacl.secretbox.nonceLength);
  var encObj = nacl.secretbox(nacl.util.decodeUTF8(string), nonce, pwDerivedKey);
  var encString = { 'encStr': nacl.util.encodeBase64(encObj),
                    'nonce': nacl.util.encodeBase64(nonce)};
  return encString;
};
KeyStore._encryptString = encryptString

KeyStore._decryptString = function (encryptedStr, pwDerivedKey) {

  var secretbox = nacl.util.decodeBase64(encryptedStr.encStr);
  var nonce = nacl.util.decodeBase64(encryptedStr.nonce);

  var decryptedStr = nacl.secretbox.open(secretbox, nonce, pwDerivedKey);

  if (decryptedStr === undefined) {
    throw new Error("Decryption failed!");
  }

  return nacl.util.encodeUTF8(decryptedStr);
};

KeyStore._encryptKey = function (privKey, pwDerivedKey) {

  var privKeyArray = nacl_decodeHex(privKey);
  var nonce = nacl.randomBytes(nacl.secretbox.nonceLength);

  var encKey = nacl.secretbox(privKeyArray, nonce, pwDerivedKey);
  encKey = { 'key': nacl.util.encodeBase64(encKey), 'nonce': nacl.util.encodeBase64(nonce)};

  return encKey;
};

KeyStore._decryptKey = function (encryptedKey, pwDerivedKey) {

  var secretbox = nacl.util.decodeBase64(encryptedKey.key);
  var nonce = nacl.util.decodeBase64(encryptedKey.nonce);
  var decryptedKey = nacl.secretbox.open(secretbox, nonce, pwDerivedKey);

  if (decryptedKey === undefined) {
    throw new Error("Decryption failed!");
  }

  return nacl_encodeHex(decryptedKey);
};

KeyStore._computeAddressFromPrivKey = function (privKey) {
  var keyPair = ec.genKeyPair();
  keyPair._importPrivate(privKey, 'hex');
  var compact = false;
  var pubKey = keyPair.getPublic(compact, 'hex').slice(2);
  var pubKeyWordArray = CryptoJS.enc.Hex.parse(pubKey);
  var hash = CryptoJS.SHA3(pubKeyWordArray, { outputLength: 256 });
  var address = hash.toString(CryptoJS.enc.Hex).slice(24);

  return address;
};

KeyStore._computePubkeyFromPrivKey = function (privKey, curve) {

  if (curve !== 'curve25519') {
    throw new Error('KeyStore._computePubkeyFromPrivKey: Only "curve25519" supported.')
  }

  var privKeyBase64 = (new Buffer(privKey, 'hex')).toString('base64')
  var privKeyUInt8Array = nacl.util.decodeBase64(privKeyBase64);
  var pubKey = nacl.box.keyPair.fromSecretKey(privKeyUInt8Array).publicKey;
  var pubKeyBase64 = nacl.util.encodeBase64(pubKey);
  var pubKeyHex = (new Buffer(pubKeyBase64, 'base64')).toString('hex');

  return pubKeyHex;
}

KeyStore.prototype._generatePrivKeys = function(pwDerivedKey, n, hdPathString) {

  if(!this.isDerivedKeyCorrect(pwDerivedKey)) {
    throw new Error("Incorrect derived key!");
  }

  if (hdPathString === undefined) {
    hdPathString = this.defaultHdPathString;
  }

  var hdRoot = KeyStore._decryptString(this.ksData[hdPathString].encHdPathPriv, pwDerivedKey);

  if (hdRoot.length === 0) {
    throw new Error('Provided password derived key is wrong');
  }

  var keys = [];
  for (var i = 0; i < n; i++){
    var hdprivkey = new bitcore.HDPrivateKey(hdRoot).derive(this.ksData[hdPathString].hdIndex++);
    var privkeyBuf = hdprivkey.privateKey.toBuffer();

    var privkeyHex = privkeyBuf.toString('hex');
    if (privkeyBuf.length < 16) {
      // Way too small key, something must have gone wrong
      // Halt and catch fire
      throw new Error('Private key suspiciously small: < 16 bytes. Aborting!');
    }
    else if (privkeyBuf.length < 32) {
      // Pad private key if too short
      // bitcore has a bug where it sometimes returns
      // truncated keys
      privkeyHex = leftPadString(privkeyBuf.toString('hex'), '0', 64);
    }
    else if (privkeyBuf.length > 32) {
      throw new Error('Private key larger than 32 bytes. Aborting!');
    }

    var encPrivKey = KeyStore._encryptKey(privkeyHex, pwDerivedKey);
    keys[i] = {
      privKey: privkeyHex,
      encPrivKey: encPrivKey
    }
  }

  return keys;
};


// This function is tested using the test vectors here:
// http://www.di-mgt.com.au/sha_testvectors.html
KeyStore._concatAndSha256 = function(entropyBuf0, entropyBuf1) {

  var totalEnt = Buffer.concat([entropyBuf0, entropyBuf1]);
  if (totalEnt.length !== entropyBuf0.length + entropyBuf1.length) {
    throw new Error('generateRandomSeed: Logic error! Concatenation of entropy sources failed.')
  }

  var hashedEnt = Hash.sha256(totalEnt);

  return hashedEnt;
}

// External static functions


// Generates a random seed. If the optional string
// extraEntropy is set, a random set of entropy
// is created, then concatenated with extraEntropy
// and hashed to produce the entropy that gives the seed.
// Thus if extraEntropy comes from a high-entropy source
// (like dice) it can give some protection from a bad RNG.
// If extraEntropy is not set, the random number generator
// is used directly.

KeyStore.generateRandomSeed = function(extraEntropy) {

  var seed = '';
  if (extraEntropy === undefined) {
    seed = new Mnemonic(Mnemonic.Words.ENGLISH);
  }
  else if (typeof extraEntropy === 'string') {
    var entBuf = new Buffer(extraEntropy);
    var randBuf = Random.getRandomBuffer(256 / 8);
    var hashedEnt = this._concatAndSha256(randBuf, entBuf).slice(0, 128 / 8);
    seed = new Mnemonic(hashedEnt, Mnemonic.Words.ENGLISH);
  }
  else {
    throw new Error('generateRandomSeed: extraEntropy is set but not a string.')
  }

  return seed.toString();
};

// Takes keystore serialized as string and returns an instance of KeyStore
KeyStore.deserialize = function (keystore) {
  var jsonKS = JSON.parse(keystore);

  if (jsonKS.version === undefined || jsonKS.version === 1) {
    throw new Error('Old version of serialized keystore. Please use KeyStore.upgradeOldSerialized() to convert it to the latest version.')
  }

  // Create keystore
  var keystoreX = new KeyStore();

  keystoreX.encSeed       = jsonKS.encSeed;
  keystoreX.encHdRootPriv = jsonKS.encHdRootPriv;
  keystoreX.ksData        = jsonKS.ksData;
  keystoreX.salt          = jsonKS.salt || defaultSalt;

  // Set the defaultHdPathString to an entry that is actuall in the
  // deserialized key store, otherwise the keystore will operate with
  // a default path that might not even be present in the deserialized
  // keystore
  keystoreX.defaultHdPathString = Object.keys(jsonKS.ksData).shift();

  return keystoreX;
};

// External API functions

KeyStore.prototype.serialize = function () {
  var jsonKS = {'encSeed': this.encSeed,
                'ksData' : this.ksData,
                'encHdRootPriv' : this.encHdRootPriv,
                'salt': this.salt || defaultSalt,
                'version' : this.version};

  return JSON.stringify(jsonKS);
};

KeyStore.deriveKeyFromPassword = function(password, salt, callback) {

  // Do not require salt, and default it to 'lightwalletSalt'
  // (for backwards compatibility)
  if (!callback && typeof salt === 'function') {
    callback = salt
    salt = defaultSalt
  } else if (!salt && typeof callback === 'function') {
    salt = defaultSalt
  }

  var logN = 14;
  var r = 8;
  var dkLen = 32;
  var interruptStep = 200;

  var cb = function(derKey) {
    try{
      var ui8arr = (new Uint8Array(derKey));
      callback(null, ui8arr);
    } catch (err) {
      callback(err);
    }
  }

  scrypt(password, salt, logN, r, dkLen, interruptStep, cb, null);
}

module.exports = KeyStore;
