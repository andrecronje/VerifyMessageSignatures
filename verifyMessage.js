const EthJS = require('ethereumjs-util')
verifySignedMessage()


function getNakedAddress(address) {
    return address.toLowerCase().replace('0x', '');
}
function getTrezorHash(msg) {
    return EthJS.sha3(Buffer.concat([EthJS.toBuffer('\x19Ethereum Signed Message:\n'), getTrezorLenBuf(msg.length), EthJS.toBuffer(msg)]));
};
function verifySignedMessage() {
    try {
        //var json = JSON.parse(message);
        var json = {
          address: "0x",
          msg: "msg",
          sig: "0xf058408ab0bbb2ab4b065b3b748ddb38d868cefa69bf63539535cec3cb4ae9f77ecfa9b3c5ee8f55010081f9d412a7b130597694108e96a6163a765c24759fab1c",
          version: "3",
          signer: "web3"
        }
        var sig = new Buffer(getNakedAddress(json.sig), 'hex');
        if (sig.length != 65) {
          console.log('Error length')
        }
        sig[64] = sig[64] == 0 || sig[64] == 1 ? sig[64] + 27 : sig[64];
        var hash = EthJS.hashPersonalMessage(EthJS.toBuffer(json.msg));
        if (json.version == '3') {
            if (json.signer == 'trezor') {
                hash = getTrezorHash(json.msg);
            }
        } else if (json.version == '1') {
            hash = EthJS.sha3(json.msg);
        }
        var pubKey = EthJS.ecrecover(hash, sig[64], sig.slice(0, 32), sig.slice(32, 64));
        if (getNakedAddress(json.address) != EthJS.pubToAddress(pubKey).toString('hex')) {
          console.log('Other Error')
        } else {
          console.log(getNakedAddress(json.address))
          console.log(EthJS.pubToAddress(pubKey).toString('hex'))
          var verifiedMsg = {
              address: json.address,
              msg: json.msg,
              sig: json.sig,
              version: json.version
          };
          console.log(verifiedMsg)
        }
    } catch (e) {
        console.log(e)
    }
};

function verifymessagesignature() {

  console.log('verifymessagesignature');
  
  /*{
    "address": "0x",
    "msg": "msg",
    "sig": "0xf058408ab0bbb2ab4b065b3b748ddb38d868cefa69bf63539535cec3cb4ae9f77ecfa9b3c5ee8f55010081f9d412a7b130597694108e96a6163a765c24759fab1c",
    "version": "3",
    "signer": "web3"
  }*/
  
  var addrHex = '0x'
  addrHex = addrHex.replace("0x", "").toLowerCase();

  var message = 'msg'
  var signatureHex = '0xf058408ab0bbb2ab4b065b3b748ddb38d868cefa69bf63539535cec3cb4ae9f77ecfa9b3c5ee8f55010081f9d412a7b130597694108e96a6163a765c24759fab1c'

  try {
      var msgSha = EthJS.sha3(message);
      var sigDecoded = EthJS.fromRpcSig(signatureHex);

      var recoveredPub = EthJS.ecrecover(msgSha, sigDecoded.v, sigDecoded.r, sigDecoded.s)          
      var recoveredAddress = EthJS.pubToAddress(recoveredPub).toString("hex");
      
      console.log(recoveredAddress)
      console.log(addrHex)

      if (recoveredAddress == addrHex) {
          console.log("Signature Matches")
      } else {
          console.log("Signature Does not Match")
      }
  }
  catch (err) {
      console.log(err)
  }
}
generateSignedMsg = function () {
    try {
        var thisMessage = $scope.signMsg.message;
        var hwType = $scope.wallet.getHWType();

        // Sign via MetaMask
        if (typeof hwType != "undefined" && hwType == "web3") {

            var msg = ethUtil.bufferToHex(new Buffer(thisMessage, 'utf8'));
            var signingAddr = web3.eth.accounts[0];
            var params = [msg, signingAddr];
            var method = 'personal_sign';

            web3.currentProvider.sendAsync({
                method: method,
                params: params,
                signingAddr: signingAddr
            }, function (err, result) {
                if (err) return $scope.notifier.danger(err);
                if (result.error) return $scope.notifier.danger(result.error);
                $scope.signMsg.signedMsg = JSON.stringify({
                    address: signingAddr,
                    msg: thisMessage,
                    sig: result.result,
                    version: '3',
                    signer: 'web3'
                }, null, 2);
                $scope.notifier.success('Successfully Signed Message with ' + signingAddr);
            });

            // Sign via Ledger
        } else if (typeof hwType != "undefined" && hwType == "ledger") {
            var msg = Buffer.from(thisMessage).toString("hex");
            var app = new ledgerEth($scope.wallet.getHWTransport());
            var localCallback = function localCallback(signed, error) {
                if (typeof error != "undefined") {
                    error = error.errorCode ? u2f.getErrorByCode(error.errorCode) : error;
                    if (callback !== undefined) callback({
                        isError: true,
                        error: error
                    });
                    return;
                }
                var combined = signed['r'] + signed['s'] + signed['v'];
                var combinedHex = combined.toString('hex');
                var signingAddr = $scope.wallet.getAddressString();
                $scope.signMsg.signedMsg = JSON.stringify({
                    address: $scope.wallet.getAddressString(),
                    msg: thisMessage,
                    sig: '0x' + combinedHex,
                    version: '3',
                    signer: 'ledger'
                }, null, 2);
                $scope.notifier.success('Successfully Signed Message with ' + signingAddr);
            };
            app.signPersonalMessage_async($scope.wallet.getPath(), msg, localCallback);

            // Sign via Digital Bitbox
        } else if (typeof hwType != "undefined" && hwType == "digitalBitbox") {
            var msg = ethUtil.hashPersonalMessage(ethUtil.toBuffer(thisMessage));
            var localCallback = function localCallback(signed, error) {
                if (typeof error != "undefined") {
                    error = error.errorCode ? u2f.getErrorByCode(error.errorCode) : error;
                    $scope.notifier.danger(error);
                    return;
                }
                var combined = signed['r'] + signed['s'] + signed['v'];
                var combinedHex = combined.toString('hex');
                var signingAddr = $scope.wallet.getAddressString();
                $scope.signMsg.signedMsg = JSON.stringify({
                    address: $scope.wallet.getAddressString(),
                    msg: thisMessage,
                    sig: '0x' + combinedHex,
                    version: '3',
                    signer: 'digitalBitbox'
                }, null, 2);
                $scope.notifier.success('Successfully Signed Message with ' + signingAddr);
            };
            $scope.notifier.info("Touch the LED for 3 seconds to sign the message. Or tap the LED to cancel.");
            var app = new DigitalBitboxEth($scope.wallet.getHWTransport(), '');
            app.signMessage($scope.wallet.getPath(), msg, localCallback);

            // Sign via Secalot
        } else if (typeof hwType != "undefined" && hwType == "secalot") {

            var localCallback = function localCallback(signed, error) {
                if (typeof error != "undefined") {
                    error = error.errorCode ? u2f.getErrorByCode(error.errorCode) : error;
                    $scope.notifier.danger(error);
                    return;
                }
                var combined = signed['r'] + signed['s'] + signed['v'];
                var combinedHex = combined.toString('hex');
                var signingAddr = $scope.wallet.getAddressString();
                $scope.signMsg.signedMsg = JSON.stringify({
                    address: $scope.wallet.getAddressString(),
                    msg: thisMessage,
                    sig: '0x' + combinedHex,
                    version: '3',
                    signer: 'secalot'
                }, null, 2);
                $scope.notifier.success('Successfully Signed Message with ' + signingAddr);
            };
            $scope.notifier.info("Tap a touch button on your device to confirm signing.");
            var app = new SecalotEth($scope.wallet.getHWTransport());
            app.signMessage($scope.wallet.getPath(), thisMessage, localCallback);

            // Sign via trezor
        } else if (typeof hwType != "undefined" && hwType == "trezor") {
            TrezorConnect.ethereumSignMessage($scope.wallet.getPath(), thisMessage, function (response) {
                if (response.success) {
                    $scope.signMsg.signedMsg = JSON.stringify({
                        address: '0x' + response.address,
                        msg: thisMessage,
                        sig: '0x' + response.signature,
                        version: '3',
                        signer: 'trezor'
                    }, null, 2);
                    $scope.notifier.success('Successfully Signed Message with ' + $scope.wallet.getAddressString());
                } else {
                    $scope.notifier.danger(response.error);
                }
            });

            // Sign via PK
        } else {
            var msg = ethUtil.hashPersonalMessage(ethUtil.toBuffer(thisMessage));
            var signed = ethUtil.ecsign(msg, $scope.wallet.getPrivateKey());
            var combined = Buffer.concat([Buffer.from(signed.r), Buffer.from(signed.s), Buffer.from([signed.v])]);
            var combinedHex = combined.toString('hex');
            var signingAddr = $scope.wallet.getAddressString();
            $scope.signMsg.signedMsg = JSON.stringify({
                address: $scope.wallet.getAddressString(),
                msg: thisMessage,
                sig: '0x' + combinedHex,
                version: '3',
                signer: 'MEW'
            }, null, 2);
            $scope.notifier.success('Successfully Signed Message with ' + signingAddr);
        }
    } catch (e) {
        $scope.notifier.danger(e);
    }
};