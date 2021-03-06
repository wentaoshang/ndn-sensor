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

var DataStat = function DataStat (prfx, duration) {
  this.prefix = prfx; // prefix for the data namespace
  this.duration = duration; // time span of the data to be fetched
  this.range = null; // array of two integers [start, end], the time range within which we want to fetch the data
  
  this.x = [];
  this.ts = [];
  this.y1 = [];
  this.y2 = [];
  this.sample_num = 0;
};

var display_time = function (container) {
  var len = dataStat.ts.length;
  
  container.innerHTML = '<table style="width: 100%; margin-top: -12px"><tr>' + 
  '<td width="20%">' + (new Date(dataStat.ts[0])).toTimeString().substr(0, 8) + '</td>' + 
  '<td width="20%">' + (new Date(dataStat.ts[Math.floor(len / 5)])).toTimeString().substr(0, 8) + '</td>' + 
  '<td width="20%">' + (new Date(dataStat.ts[Math.floor(len / 5 * 2)])).toTimeString().substr(0, 8) + '</td>' +
  '<td width="20%">' + (new Date(dataStat.ts[Math.floor(len / 5 * 3)])).toTimeString().substr(0, 8) + '</td>' +
  '<td width="15%">' + (new Date(dataStat.ts[Math.floor(len / 5 * 4)])).toTimeString().substr(0, 8) + '</td>' +
  '<td width="5%" align="right">' + (new Date(dataStat.ts[len - 1])).toTimeString().substr(0, 8) + '</td></tr></table>';
};

var display_data = function () {
  $("#loader").fadeOut(50);
  $("#summary").fadeIn(100);
  
  dataStat.ts.reverse ();
  dataStat.y1.reverse ();
  
  var data_info = data_points[data_index];
  //console.log(data_info);
  $("#bacname").text(data_info.lable + ' (in ' + data_info.unit + '): ');
  
  var pw = document.getElementById('pw');
  
  // Data Format:
  var series_data = [[dataStat.x, dataStat.y1]];
  
  // TimeSeries Template Options
  var options = {
    // Container to render inside of
  container : pw,
  // Data for detail (top chart) and summary (bottom chart)
  data : {
    detail : series_data,
    summary : series_data
    },
  // An initial selection
  selection : {
    data : {
      x : {
	min : Math.round(0.191 * dataStat.sample_num),
	max : Math.round(0.382 * dataStat.sample_num)
      }
    }
  },
  defaults : {
    detail : {
      config : {
	yaxis : {
	  //autoscale : false,
	  showLabels : true,
	  noTicks : 6,
	  //ticks : [[268, ''], 270, 272, 274, 276, 278, 280],
	  //min : 268,
	  //max : 280
	}
      }
    }
  }
  };
  
  // Create the TimeSeries
  new envision.templates.TimeSeries(options);
  
  var pw_time = document.getElementById('pw_time');
  display_time(pw_time);
};

var onData = function (inst, data) {
  console.log("Received data: " + data.name.toUri());
  fetchDecryptionKey(data);
//     CpsMelnitzPolicy.verify(face, data, function (result) {
// 	if (result == VerifyResult.SUCCESS) {
// 	    fetchDecryptionKey(data);
// 	} else if (result == VerifyResult.FAILURE)
// 	    console.log('Data verification failed.');
// 	else if (result == VerifyResult.TIMEOUT)
// 	    console.log('Data verification failed due to timeout.');
//     });
};

//var key = CryptoJS.enc.Hex.parse('389ad5f8fc26f076e0ba200c9b42f669d07066032df8a33b88d49c1763f80783');
var iv_len = 16;
var key_ts_len = 8;

var fetchDecryptionKey = function (data) {
  var key_ts = data.content.subarray(0, key_ts_len);
  
  var onKeyData = function (inst, key_data) {
    //console.log("Decryption key name: " + key_data.name.toUri());
    //CpsMelnitzPolicy.verify(face, key_data, function (result) {
    //if (result == VerifyResult.SUCCESS) {
    var ciphertext = DataUtils.toHex(key_data.content);
    //console.log(ciphertext);
    var rsa = new RSAKey();
    rsa.readPrivateKeyFromPEMString(usrDefaultKey.privatePem);
    var sym_key = rsa.decrypt(ciphertext);
    //console.log(sym_key);
    processData(data, sym_key);
    //} else if (result == VerifyResult.FAILURE)
    //console.log('Sym key verification failed.');
    //else if (result == VerifyResult.TIMEOUT)
    //console.log('Sym key verification failed due to timeout.');
    //});
  };
  
  var sym_key_name = new Name('/ndn/ucla.edu/bms/melnitz/kds').append(key_ts).append(usrKeyID);
  var template = new Interest();
  template.interestLifetime = 4000;
  template.setMustBeFresh(false);

  //console.log('Fetch sym key: ' + sym_key_name.toUri());
  face.expressInterest(sym_key_name, template, onKeyData, onTimeout);
};

var processData = function (data, sym_key) {
  var data_name = data.name;
  
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
  dataStat.sample_num++;

  var tpos = data_name.components.length - 1;
  var ts = data_name.components[tpos];
  var ts_num = parseInt(DataUtils.toHex(ts.value), 16);
  //console.log(new Date(ts_num));

  if (dataStat.range == null)
    dataStat.range = [ts_num - dataStat.duration, ts_num];

  if (ts_num < dataStat.range[0] || dataStat.sample_num >= 600) {
    // We have collected enough samples. Display in time series
    display_data();
  } else {
    // Record the data samples
    dataStat.x.push(dataStat.sample_num);
    dataStat.ts.push(json_obj.ts);
    dataStat.y1.push(json_obj.val);

    // Send interest for the next content object
    var filter = new Exclude([ts, Exclude.ANY]);
    var template = new Interest();
    template.childSelector = 1;
    template.interestLifetime = 4000;
    template.exclude = filter;
    template.setMustBeFresh(true);
    
    face.expressInterest(dataStat.prefix, template, onData, onTimeout);
  }
};

var onTimeout = function (inst) {
  console.log("Interest timeout: " + inst.name.toUri());
  
  if (dataStat.sample_num > 0) {
    // Display what we have up to now
    display_data();
  } else {
    $("#loader").hide();
    $('#error').append("<p>Currently I'm connected to " + hub + ".</p>");
    $("#error").fadeIn(100);
  }
};

var dataStat;
function get_data (duration) {
  var name = new Name(data_points[data_index].name);
  dataStat = new DataStat(name, duration);

  var template = new Interest();
  template.childSelector = 1;
  template.setMustBeFresh(true);
  template.interestLifetime = 4000;
  
  face.expressInterest(name, template, onData, onTimeout);
}

var face;
var hub = "borges.metwi.ucla.edu";
var data_index = 0;

$(document).ready(function () {
    //console.log(window.location.href);
    var pat = /#(.*)$/;
    var res = pat.exec(window.location.href);
    if (res != null)
      {
	data_index = parseInt(res[1]);
	//console.log(data_index);
      }
    face = new Face({port:9696, host:hub});
    get_data(3600000);
});
