const express = require('express')
const app = express()

app.get('/', function (req, res) {
    res.send('Hello World!')
  });

  app.get('/sign', function(req,res){

    var SignedXml = require('xml-crypto').SignedXml	  
	  , fs = require('fs')

    var xml = "<library>" +
                "<book id='mybook'>" +
                  "<name>Harry Potter</name>" +
                "</book>" +
              "</library>"

    var sig = new SignedXml()
    sig.addReference("//*[local-name(.)='book']")   
    sig.keyInfoProvider = new MyKeyInfo();
    //sig.signingKey = fs.readFileSync("./certs/test-private/serialnumber-key.pem")
    sig.signingKey = readPrivateKeyFromProtectedPem('./certs/test-private/serialnumber-key.pem', 'Cl3@n3n3rgy');
    
    sig.computeSignature(xml)
    fs.writeFileSync("output/signed.xml", sig.getSignedXml())

  });

  app.post('/verify', function (req, res) {
    var select = require('xml-crypto').xpath, 
        dom = require('xmldom').DOMParser, 
        SignedXml = require('xml-crypto').SignedXml, 
        FileKeyInfo = require('xml-crypto').FileKeyInfo, 
        fs = require('fs');

        const testFolder = './testfiles/';
        
        fs.readdir(testFolder, (err, files) => {
          files.forEach(file => {


            console.log(file);
            var xml = fs.readFileSync(testFolder + file).toString();
            var doc = new dom().parseFromString(xml)    

            var signature = select(doc, "/*/*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']")[0]
            var certificate = select(doc, "//*[local-name()='X509Certificate']")[0].textContent;
    

            certificate = "-----BEGIN CERTIFICATE-----\n" + certificate + "\n-----END CERTIFICATE-----";
            var pemFileName ="certs\\" + file + ".pem"; 
            fs.writeFile(pemFileName, certificate, function(err) {
              if(err) {
                  return console.log(err);
              }
          
              console.log("************" + file );

              var sig = new SignedXml()
              //sig.keyInfoProvider = new FileKeyInfo("certs\\formbay.public.pem")
              sig.keyInfoProvider = new FileKeyInfo(pemFileName) ;//"certs\\test.pem")
              //sig.signingKey= certificate;
              sig.loadSignature(signature)
              
              //console.log(sig);
              var res = sig.checkSignature(xml)
              if (!res) {
                console.log("Failed", sig.validationErrors);
              } 
              else {
                console.log(res + " - Done");
              };
            }); 
              

          });
        })


  var xml = fs.readFileSync("formbayResponse.xml", "utf16le").toString();
 


    res.send('Got a POST request')
  });

  app.put('/user', function (req, res) {
    res.send('Got a PUT request at /user')
  });

  app.delete('/user', function (req, res) {
    res.send('Got a DELETE request at /user')
  });


  function readPrivateKeyFromProtectedPem(path, passphrase){
    fs = require('fs');
    var forge = require('node-forge');
    var pki = forge.pki;

    var pem = fs.readFileSync(path).toString();
    var privateKey = pki.decryptRsaPrivateKey(pem, passphrase);
    return pki.privateKeyToPem(privateKey);
}

app.listen(3000, () => console.log('Example app listening on port 3000!'));


function MyKeyInfo() {
  this.getKeyInfo = function(key, prefix) {
      prefix = prefix || ''
      prefix = prefix ? prefix + ':' : prefix;
      console.log("*************** fix this my ");
      var rawX509 = fs.readFileSync("certs/test-private/serialnumber-raw.pem", "utf8");
    return "<" + prefix + "X509Data>"+ rawX509 +"</" + prefix + "X509Data>"
  }
  this.getKey = function(keyInfo) {
    //you can use the keyInfo parameter to extract the key in any way you want      
    return fs.readFileSync("certs/test-private/serialnumber-crt.pem")
  }
}