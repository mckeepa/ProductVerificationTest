var select = require('xml-crypto').xpath, 
        dom = require('xmldom').DOMParser, 
        SignedXml = require('xml-crypto').SignedXml, 
        FileKeyInfo = require('xml-crypto').FileKeyInfo, 
        fs = require('fs'),
        forge = require('node-forge')
        DEBUG = false, FAIL = false, NOFORMATTING = false;


function sign(dir, file, type) {
  return new Promise((resolve, reject) => {
    try {
      //log("Signing [" + dir + "/" + file + "]")
      var xml = removeFormattingIfRequired(fs.readFileSync(dir + "/" + file, 'utf-8'));
      var sig = new SignedXml()
      addReferenceToSignature(sig, type)
      sig.keyInfoProvider = new MyKeyInfo();
      sig.canonicalizationAlgorithm = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
      sig.signingKey = readPrivateKeyFromProtectedPem('./certs/test-private/serialnumber-key.pem', 'Cl3@n3n3rgy');
      sig.computeSignature(xml)
      fs.writeFileSync(dir.replace('unsigned', 'signed') + "/" + file, sig.getSignedXml())
      log("Signed [" + dir.replace('unsigned', 'signed') + "/" + file + "]")
      resolve(dir.replace('unsigned', 'signed') + "/" + file)  
    } catch(err) {
      console.error(err)
      reject(dir.replace('unsigned', 'signed') + "/" + file)
    }
  })
}

function verify(file, cert) {
  try {
    var xml = failVerificationIfRequired(fs.readFileSync(file, 'utf-8'));
    var doc = new dom().parseFromString(xml)
    var signature = select(doc, "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']")[0]
    var sig = new SignedXml();
    sig.keyInfoProvider = new MyKeyInfo();
    sig.loadSignature(signature);
    var res = sig.checkSignature(xml);
    if (!res) {
      console.error("ERROR [" + file + "]" + sig.validationErrors);
    } else {
      log("SUCCESS [" + file + "]");
    }
  } catch(err) {
    console.error("ERROR [" + file + "] : " + err)
  }
}


function addReferenceToSignature(sig, type) {
  if(type=='product') {
    sig.addReference("//*[local-name(.)='ProductsVerified']", ["http://www.w3.org/2000/09/xmldsig#enveloped-signature", "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"])
  } else if(type=='installationresponse') {
    sig.addReference("//*[local-name(.)='InstallationProductVerification']", ["http://www.w3.org/2000/09/xmldsig#enveloped-signature", "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"])
  } else if(type=='recrequest') {
    sig.addReference("//*[local-name(.)='Registration']", ["http://www.w3.org/TR/2001/REC-xml-c14n-20010315"])
  } else {
    sig.addReference("//*[local-name(.)='InstallationProducts']", ["http://www.w3.org/2000/09/xmldsig#enveloped-signature", "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"])
  }
}

function readPrivateKeyFromProtectedPem(path, passphrase) {
  var pki = forge.pki;
  var pem = fs.readFileSync(path).toString();
  var privateKey = pki.decryptRsaPrivateKey(pem, passphrase);
  return pki.privateKeyToPem(privateKey);
}

function MyKeyInfo() {
  this.getKeyInfo = function(key, prefix) {
      prefix = prefix || ''
      prefix = prefix ? prefix + ':' : prefix;
      var rawX509 = fs.readFileSync("certs/test-private/serialnumber-raw.pem", "utf8");
    return "<" + prefix + "X509Data>"+ rawX509 +"</" + prefix + "X509Data>"
  }
  this.getKey = function(keyInfo) {
    //you can use the keyInfo parameter to extract the key in any way you want      
    return fs.readFileSync("certs/test-private/serialnumber-crt.pem")
  }
}


function signAndVerifyFilesInDirectory(dir) {
  //log("Reading directory [" + dir + "]")
  createSignedDirectoryIfItDoesNotExist(dir)
  var files = fs.readdirSync(dir);
  files.forEach(file => {
    if (fs.statSync(dir + '/' + file).isDirectory()) {
      signAndVerifyFilesInDirectory(dir + '/' + file);
    } else {
      //log("Processing file [" + dir + "/" + file + "]");
      sign(dir, file, 'product').then((signedFile) => {
        verify(signedFile)
      })
    }
  });
};

function VerifyFilesInDirectory(dir) {
  //log("Reading directory [" + dir + "]")
  createSignedDirectoryIfItDoesNotExist(dir)
  var files = fs.readdirSync(dir);
  files.forEach(file => {
    if (fs.statSync(dir + '/' + file).isDirectory()) {
      VerifyFilesInDirectory(dir + '/' + file);
    } else {
      //log("Processing file [" + dir + "/" + file + "]");
      verify(dir + '/' + file);

    }
  });
};


function createSignedDirectoryIfItDoesNotExist(dir) {
  var udir = dir.replace('unsigned', 'signed')
  if(!fs.exists(udir)) {
    try {
      fs.mkdirSync(udir);
    } catch(err) {
      //console.error(err)
    }
  }
}

function failVerificationIfRequired(xml) {
  if(FAIL) {
      xml = xml.replace(/RequestedDateTime/g, "RDT") //uncomment this line to make the verification fail    
  }
  return xml;
}

function removeFormattingIfRequired(xml) {
  if(NOFORMATTING) {
    xml = xml.replace(/>\s*</g, '><');
  }
  return xml;
}

function log(msg) {
  if(DEBUG) {
    console.log(msg)
  }
}

function UseCommandArguments() {
  // Arguments are in the format  " debug:true  "
  process.argv.forEach(function (val, index, array) {
    var arg = val.split(':');
    
    if(arg[0].toUpperCase()=="DEBUG" ) {
      if (arg[1].toUpperCase()=="TRUE") { DEBUG = true}
      else DEBUG =false;
      console.log("DEBUG: " + DEBUG )
    };
  });

}

UseCommandArguments();
signAndVerifyFilesInDirectory('./unsigned');
VerifyFilesInDirectory('./signed');