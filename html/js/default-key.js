var usrDefaultKey = {
 privatePem :
 "-----BEGIN RSA PRIVATE KEY-----\n" +
 "MIICXAIBAAKBgQDDNpgZFC23yGSLsMo8mzTcmdnipkUHI+i8CYagTEqHO+PnejF9\n" +
 "Ep/D+MBvEtPXHSgExsDCHP8X7B6If1df58OWXB9GPnXUsAsjKKXgOaKoMJr9NZXP\n" +
 "qlBbJSrT0h5590hCm2ePPUVkvJKsOX6gCFnptbLzF7pvb3zKDc+zXjyHPwIDAQAB\n" +
 "AoGBALR4BTayI+3SkblekChlaAJFLVxOUGRgeylTOSV6QjAxWulFWvkAvbijf+tv\n" +
 "oW4uIy//OnZ57g6EmFmiN/mOvo3meBvWijHxUJG1suKrEgG8Gm0LZn0CyycTtutl\n" +
 "ziSDJ3F4whEZfuqciAFOTTgAXPRHMa/cZbSDo4aGR5mbqE0ZAkEA3+HmB/1SgwMB\n" +
 "bopCmkh+sslFhtD2xUxlXnlC3ur4rOmjtH7YE0Q2UDsJFj9eg/BA4fQ/orh9usGv\n" +
 "AVph7o6lswJBAN830Xc7cjxeF3vQyJk1vqqPf15FGvkraq7gHb5MPAtofh78PtzD\n" +
 "+hyblvWAYBstR/K6up1KG+LP6RXA43q7qkUCQA49540wjzQoV8n5X51C6VRkO1kF\n" +
 "J/2LC5PD8P4PQnx1bGWKACLRnwbhioVwyIlqGiaFjBrE07KyqXhTkJFFX8MCQAjW\n" +
 "qfmhpfVT+HQToU3HvgP86Jsv+1Bwcqn3/9WAKUR+X7gUXtzY+bdWRdT0v1l0Iowu\n" +
 "7qK5w37oop8U4y0B700CQBKRizBt1Nc02UMDzdamQsgnRjuIjlfmryfZpemyx238\n" +
 "Q0s2+cKlqbfDOUY/CAj/z1M6RaISQ0TawCX9NIGa9GI=",
 publicPem :
 "-----BEGIN PUBLIC KEY-----\n" +
 "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDDNpgZFC23yGSLsMo8mzTcmdni\n" +
 "pkUHI+i8CYagTEqHO+PnejF9Ep/D+MBvEtPXHSgExsDCHP8X7B6If1df58OWXB9G\n" +
 "PnXUsAsjKKXgOaKoMJr9NZXPqlBbJSrT0h5590hCm2ePPUVkvJKsOX6gCFnptbLz\n" +
 "F7pvb3zKDc+zXjyHPwIDAQAB\n" +
 "-----END PUBLIC KEY-----"
};

function getKeyID (key) {
  // Remove the '-----XXX-----' from the beginning and the end of the public key
  // and also remove any \n in the public key string
  var pub = key.publicPem;
  var lines = pub.split('\n');
  pub = "";
  for (var i = 1; i < lines.length - 1; i++)
    pub += lines[i];
  var hex = b64tohex(pub);
  var der = new Uint8Array(Math.floor(hex.length / 2));
  var i = 0;
  hex.replace(/(..)/g, function(ss) {
      der[i++] = parseInt(ss, 16);
    });
  var hash = require("crypto").createHash('sha256');
  hash.update(der);
  return hash.digest();
}

var usrKeyID = getKeyID(usrDefaultKey);
