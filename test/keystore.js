var expect = require('chai').expect
var keyStore = require('../lib/keystore')
var fixtures = require('./fixtures/keystore')
var Promise = require('bluebird')

var defaultHdPathString = "m/0'/0'/0'";

var addrprivkeyvector = require('./fixtures/addrprivkey100.json')

describe("Keystore", function() {
  describe("Constructor", function() {

    it("returns empty keystore when no args are passed", function(done) {
      var ks = new keyStore()
      // expect(ks.getAddresses()).to.equal(ks.ksData[ks.defaultHdPathString].addresses);

      // No values are set
      expect(ks.encSeed).to.equal(undefined)
      expect(ks.ksData[ks.defaultHdPathString].encHdRootPrivkey).to.equal(undefined)
      expect(ks.ksData[ks.defaultHdPathString].encPrivKeys).to.deep.equal({})
      expect(ks.ksData[ks.defaultHdPathString].addresses).to.deep.equal([])
      done();
    });

    it("sets the hd index to 0", function(done) {
      var ks = new keyStore(fixtures.valid[0].mnSeed, Uint8Array.from(fixtures.valid[0].pwDerivedKey))
      expect(ks.ksData[ks.defaultHdPathString].hdIndex).to.equal(0)
      done();
    })

    it("returns keystore with an encrypted seed set when give mnemonic and pwDerivedKey", function(done) {
      var ks = new keyStore(fixtures.valid[0].mnSeed, Uint8Array.from(fixtures.valid[0].pwDerivedKey))
      expect(ks.encSeed).to.not.equal(undefined);
      var decryptedPaddedSeed = keyStore._decryptString(ks.encSeed, Uint8Array.from(fixtures.valid[0].pwDerivedKey));
      // Check padding
      expect(decryptedPaddedSeed.length).to.equal(120);
      expect(decryptedPaddedSeed.trim()).to.equal(fixtures.valid[0].mnSeed);
      done();
    });

    it("throws error if invalid mnemonic is given", function(done) {
      // invalid described in bitcore-mnemonic
      expect(function(){
        new keyStore("als", Uint8Array.from(fixtures.valid[0].pwDerivedKey))
      }).to.throw(Error)
      done();
    });

    it("throws error if pwDerivedKey not given", function(done) {
      // add
      done();
    });
  });

  // Can't directly test the encrypt/decrypt functions
  // since salt and iv is used.
  describe("_encryptString _decryptString", function() {

    fixtures.valid.forEach(function (f) {
      it('encrypts the seed then returns same seed decrypted ' + '"' + f.mnSeed.substring(0,25) + '..."', function (done) {

        var encryptedString = keyStore._encryptString(f.mnSeed, Uint8Array.from(f.pwDerivedKey))
        var decryptedString = keyStore._decryptString(encryptedString, Uint8Array.from(f.pwDerivedKey))

        expect(decryptedString).to.equal(f.mnSeed)
        done();
      })
    })
  });

  describe("_encryptKey _decryptKey", function() {

    fixtures.valid.forEach(function (f) {
      it('encrypts the key then returns same key decrypted ' + '"' + f.privKeyHex.substring(0,15) + '..."', function (done) {

        var encryptedKey = keyStore._encryptKey(f.privKeyHex, Uint8Array.from(f.pwDerivedKey))
        var decryptedKey = keyStore._decryptKey(encryptedKey, Uint8Array.from(f.pwDerivedKey))

        expect(decryptedKey).to.equal(f.privKeyHex)
        done();
      })
    })
  });

  describe("_computeAddressFromPrivKey", function() {
    fixtures.valid.forEach(function (f) {
      it('generates valid address from private key ' + '"' + f.privKeyHex.substring(0,15) + '..."', function (done) {
        var address = keyStore._computeAddressFromPrivKey(f.privKeyHex)
        expect(address).to.equal(f.address)
        done();
      })
    })

    addrprivkeyvector.forEach(function (f) {
      it('generates valid address from private key ' + '"' + f.key.substring(0,15) + '..."', function (done) {
        var address = keyStore._computeAddressFromPrivKey(f.key)
        expect(address).to.equal(f.addr)
        done();
      })
    })
  });

  describe("serialize deserialize", function() {
    it("serializes empty keystore with salt and returns same empty keystore when deserialized ", function(done) {
      var fixture = fixtures.valid[0]
      var origKS = new keyStore(fixture.mnSeed, Uint8Array.from(fixture.pwDerivedKey), defaultHdPathString, fixture.salt)
      var serKS = origKS.serialize()
      var deserKS = keyStore.deserialize(serKS)

      // Retains all attributes properly
      expect(deserKS.encSeed).to.deep.equal(origKS.encSeed)
      expect(deserKS.encHdRootPriv).to.deep.equal(origKS.encHdRootPriv)
      expect(deserKS.ksData).to.deep.equal(origKS.ksData)
      expect(deserKS.version).to.equal(origKS.version)
      expect(deserKS.salt).to.equal(origKS.salt)
      done();
    });


    it("serializes empty keystore and returns same empty keystore when deserialized  without a salt", function(done) {
      var fixture = fixtures.valid[1]
      var origKS = new keyStore(fixture.mnSeed, Uint8Array.from(fixture.pwDerivedKey))
      var serKS = origKS.serialize()
      var deserKS = keyStore.deserialize(serKS)

      // Retains all attributes properly
      expect(deserKS.encSeed).to.deep.equal(origKS.encSeed)
      expect(deserKS.encHdRootPriv).to.deep.equal(origKS.encHdRootPriv)
      expect(deserKS.ksData).to.deep.equal(origKS.ksData)
      expect(deserKS.version).to.equal(origKS.version)
      expect(deserKS.salt).to.equal(origKS.salt)
      done();
    });
});

});
