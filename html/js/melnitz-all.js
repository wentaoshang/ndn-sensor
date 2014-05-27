function UnsignedIntToArrayBuffer (value) {
  if (value <= 0)
    return new Uint8Array([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
  
  // Encode into 64 bits.
  var size = 8;
  var result = new Uint8Array(size);
  var i = 0;
  while (i < 8)
    {
      //console.log(value);
      ++i;
      result[size - i] = value % 256;
      value = Math.floor(value / 256);
    }
  return result;
}

var iv_len = 16;
var key_ts_len = 8;
//var cache_key_ts = -1;
//var cache_key = null;

var onTimeout = function (inst) {
  console.log("Interest timeout: " + inst.name.toUri());
};

function draw_table () {
  for (var i = 0; i < data_points.length; i++)
    {
      var name = data_points[i].name;
      var bacnet_name = data_points[i].lable;
      var name_id = bacnet_name.replace(/\./g, '_') + '_name';
      var ts_id = bacnet_name.replace(/\./g, '_') + '_ts';
      var val_id = bacnet_name.replace(/\./g, '_') + '_val';
      var prefix = new Name(name);
      var unit = data_points[i].unit;

      $("#list").append('<tr><td style="width:75%" id="' + name_id + '">' + bacnet_name + '</td><td style="width:12%" id="' + ts_id + '">' 
			+ '</td><td style="width:8%" id="' + val_id + '"></td><td style="width:5%">' + unit + '</td></tr>' );
    }
}

function get_all_data () {
  $("#loader").fadeOut(50);
  $("#summary").fadeIn(100);

  draw_table();

  var now = new Date();
  var start = now - 600000; // in milliseconds
  console.log('Fetch data starting from ' + new Date(start) + ' (0x' + start.toString(16) + ')');
  
  var filter = new Exclude([Exclude.ANY, UnsignedIntToArrayBuffer(start)]);
  
  var template = new Interest();
  template.childSelector = 0;
  //template.minSuffixComponent = 1;
  //template.maxSuffixComponent = 2;
  template.interestLifetime = 4000;
  template.exclude = filter;
  
  //for (var i = 0; i < data_points.length; i++)
  //  {
  var recursion = function (index) {
        //var index = i;
	var name = data_points[index].name;
	var bacnet_name = data_points[index].lable;
	var prefix = new Name(name);
	var unit = data_points[index].unit;

	var name_id = bacnet_name.replace(/\./g, '_') + '_name';
	$("#" + name_id)
	  .hover(function () { $("#" + name_id).text(name); },
		 function () { $("#" + name_id).text(bacnet_name); }
		 );

	$("#" + name_id).click(function () {
	    window.open('./melnitz.html#' + index, '_self');
	  });

	var display_data = function (obj) {
	  //console.log('Trying to show data for ' + bacnet_name);

	  var ts = (new Date(obj.ts)).toLocaleTimeString();
	  var val = obj.val.toString().substr(0, 6);

	  var ts_id = bacnet_name.replace(/\./g, '_') + '_ts';
	  var val_id = bacnet_name.replace(/\./g, '_') + '_val';

	  $("#" + ts_id).text(ts);
	  $("#" + val_id).text(val);
	};

	var processData = function (data, sym_key) {
	  var data_name = data.name;
	  //console.log("Received: " + data.name.to_uri());

	  var msg = DataUtils.toHex(data.content).substr(key_ts_len * 2);
	  var iv = CryptoJS.enc.Hex.parse(msg.substr(0, iv_len * 2));
	  var ciphertext = CryptoJS.enc.Hex.parse(msg.substr(iv_len * 2));
	  var key = CryptoJS.enc.Hex.parse(sym_key);
	  var aesDecryptor = CryptoJS.algo.AES.createDecryptor(key, { iv: iv });
	  var p1 = aesDecryptor.process(ciphertext);
	  var p2 = aesDecryptor.finalize();
	  //console.log(p1.toString(CryptoJS.enc.Utf8));
	  //console.log(p2.toString(CryptoJS.enc.Utf8));

	  var json_text = p1.toString(CryptoJS.enc.Utf8) + p2.toString(CryptoJS.enc.Utf8);
	  var json_obj = jQuery.parseJSON(json_text);
	  //console.log(json_text);
	  display_data(json_obj);

	  if (index < data_points.length - 1)
	    {
              console.log('Fetch data: ' + name);
              recursion(index + 1);
            }
	};

	var fetchDecryptionKey = function (data) {
	  var key_ts = data.content.subarray(0, key_ts_len);
	  var key_ts_num = parseInt(DataUtils.toHex(key_ts), 16);
	  
	  var onKeyData = function (inst, key_data) {
	    //CpsMelnitzPolicy.verify(ndn, key_co, function (result) {
	    //	if (result == VerifyResult.SUCCESS) {
	    var ciphertext = DataUtils.toHex(key_data.content);
	    //console.log(ciphertext);
	    var rsa = new RSAKey();
	    rsa.readPrivateKeyFromPEMString(usrDefaultKey.privatePem);
	    var sym_key = rsa.decrypt(ciphertext);
	    //console.log(sym_key);
	    //cache_key = sym_key;
	    //cache_key_ts = key_ts_num;
	    processData(data, sym_key);
	    //	    } else if (result == VerifyResult.FAILURE)
	    //		console.log('Sym key verification failed.');
	    //	    else if (result == VerifyResult.TIMEOUT)
	    //		console.log('Sym key verification failed due to timeout.');
	    //});
	  };

	  var onKeyTimeout = function (inst) {
	    console.log('Interest timeout when fetching decryption key:');
	    console.log("Sym key timestamp: " + key_ts_num);
	    console.log(DataUtils.toHex(key_ts));
	    console.log(inst.name.to_uri());
	  };
	  
	  var sym_key_name = new Name('/ndn/ucla.edu/bms/melnitz/kds').append(key_ts).append(usrKeyID);

	  var template = new Interest();
	  template.interestLifetime = 4000;

	  //console.log('Fetch sym key: ' + sym_key_name.toUri());
	  face.expressInterest(sym_key_name, onKeyData, null);
	};

	var onData = function (inst, data) {
	  //console.log('Inerest name: ' + inst.name.toUri())
	  //console.log('Received data: ' + data.name.toUri());
	  //CpsMelnitzPolicy.verify(ndn, co, function (result) {
	  //	if (result == VerifyResult.SUCCESS) {
	  fetchDecryptionKey(data);
	  //	} else if (result == VerifyResult.FAILURE)
	  //	    console.log('Data verification failed.');
	  //	else if (result == VerifyResult.TIMEOUT)
	  //	    console.log('Data verification failed due to timeout.');
	  //    });
	};

	console.log('Fetch data: ' + name);

	face.expressInterest(prefix, template, onData, onTimeout);
  }; 

  recursion(0);
    // }
}

var face;
var hub = 'borges.metwi.ucla.edu';

$(document).ready(function () {
  face = new Face({port:9696, host:hub});
  // Hack!
  // face.expressInterest(new Name("/ndn/ucla.edu/bms"), 
  //   			 function (inst, data) {
  // 			     get_all_data(); 
  // 			 },
  // 			 function (inst) {});
  get_all_data();
});
