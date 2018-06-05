Generate self signed certificate and key as PEM:
  openssl req -x509 -sha256 -days 365 -newkey rsa:4096 -keyout serialnumber-key.pem -out serialnumber-crt.pem

Convert certificate and key PEM into PFX:
  openssl pkcs12 -export -in serialnumber-crt.pem -inkey serialnumber-key.pem -out serialnumber.pfx

Convert certificate PEM to DER:
  openssl x509 -inform PEM -outform DER -in serialnumber-crt.pem -out serialnumber-crt.der

Convert key PEM to DER:
  openssl rsa -inform PEM -outform DER -in serialnumber-key.pem -out serialnumber-key.der

View contents of certificate:
  openssl x509 -in serialnumber-crt.pem -text -noout > serialnumber-crt.txt


  openssl pkcs12 -in serialnumber.pfx -out certificate.cer -nodes