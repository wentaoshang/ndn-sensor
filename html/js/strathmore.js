function UnsignedIntToArrayBuffer(value) {
    if (value <= 0)
	return new Uint8Array([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
		    
    // Encode into 64 bits.
    var size = 8;
    var result = new Uint8Array(size);
    var i = 0;
    while (i < 8) {
	//console.log(value);
	++i;
	result[size - i] = value % 256;
	value = Math.floor(value / 256);
    }
    return result;
};
	
var DataStat = function DataStat(prfx, range) {
    this.prefix = prfx; // prefix for the data namespace
    this.range = range; // array of two integers [start, end], the time range within which we want to fetch the data
    
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
    
    // Draw current
    var cur = document.getElementById('current');
			
    // Data Format:
    var cur_data = [dataStat.x, dataStat.y2];
			
    // TimeSeries Template Options
    var cur_options = {
    // Container to render inside of
    container : cur,
    // Data for detail (top chart) and summary (bottom chart)
    data : {
	detail : cur_data,
	summary : cur_data
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
		    //ticks : [[220, ''], 230, 240, 250, 260, 270],
		    //min : 220,
		    //max : 270
		}
	    }
	}
    }
    };

    // Create the TimeSeries
    new envision.templates.TimeSeries(cur_options);
    
    var cur_time = document.getElementById('cur_time');
    display_time(cur_time);
    
    // Draw voltage
    var vol = document.getElementById('voltage');
    
    // Data Format:
    var vol_data = [dataStat.x, dataStat.y1];
    
    // TimeSeries Template Options
    var vol_options = {
    // Container to render inside of
    container : vol,
    // Data for detail (top chart) and summary (bottom chart)
    data : {
	detail : vol_data,
	summary : vol_data
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
    new envision.templates.TimeSeries(vol_options);
    
    var vol_time = document.getElementById('vol_time');
    display_time(vol_time);
};

var onData = function (inst, co) {
    //console.log(co.name.to_uri());
    CpsStrathmorePolicy.verify(ndn, co, function (result) {
	if (result == VerifyResult.SUCCESS) {
	    fetchDecryptionKey(co);
	} else if (result == VerifyResult.FAILURE)
	    console.log('Data verification failed.');
	else if (result == VerifyResult.TIMEOUT)
	    console.log('Data verification failed due to timeout.');
    });
};

var iv_len = 16;
var key_ts_len = 8;

var fetchDecryptionKey = function (data_co) {
    var key_ts = data_co.content.subarray(0, key_ts_len);
    
    var onKeyData = function (inst, key_co) {
	 CpsStrathmorePolicy.verify(ndn, key_co, function (result) {
	     if (result == VerifyResult.SUCCESS) {
		 var ciphertext = DataUtils.toHex(key_co.content);
		 //console.log(ciphertext);
		 var rsa = new RSAKey();
		 rsa.readPrivateKeyFromPEMString(ndn.getDefaultKey().privateToPEM());
		 var sym_key = rsa.decrypt(ciphertext);
		 //console.log(sym_key);
		 processData(data_co, sym_key);
	     } else if (result == VerifyResult.FAILURE)
		 console.log('Sym key verification failed.');
	     else if (result == VerifyResult.TIMEOUT)
		 console.log('Sym key verification failed due to timeout.');
	 });
    };

    var sym_key_name = new Name('/ndn/ucla.edu/bms/strathmore/kds').append(key_ts).appendKeyID(ndn.getDefaultKey());
    //console.log('Fetch sym key: ' + sym_key_name.to_uri());
    ndn.expressInterest(sym_key_name, null, onKeyData);
};

var processData = function (co, sym_key) {
    var co_name = co.name;
    //console.log(co_name.to_uri());
    
    var msg = DataUtils.toHex(co.content).substr(key_ts_len * 2);
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

    dataStat.sample_num++;
    
    // Record the data samples
    dataStat.x.push(dataStat.sample_num);
    dataStat.ts.push(json_obj.ts);
    dataStat.y1.push(json_obj.vlna);
    dataStat.y2.push(json_obj.la / 10);
    
    if (dataStat.sample_num >= 3600) {
	// We have collected enough samples. Display in time series
	display_data();
    } else {
	// Send interest for the next content object
	var tpos = co_name.components.length - 1;
	var ts = co_name.components[tpos];
	var ts_num = parseInt(DataUtils.toHex(ts), 16);
	//console.log(ts);
	
	var filter = new Exclude([Exclude.ANY, ts, UnsignedIntToArrayBuffer(ts_num + 1800), Exclude.ANY]);
	
	var template = new Interest();
	template.childSelector = 0;
	template.interestLifetime = 1000;
	template.exclude = filter;
				
	ndn.expressInterest(dataStat.prefix, template, onData, onTimeout);
    }
};

var onTimeout = function (inst) {
    console.log("Interest timeout: " + inst.name.to_uri());
    
    if (dataStat.sample_num > 0) {
	// Display what we have up to now
	display_data();
    } else {
	$("#loader").hide();
	$('#error').append("<p>Currently I'm connected to " + hub + ". Refresh me to try another hub.</p>");
	$("#error").fadeIn(100);
    }
};

var dataStat;
function get_data_since(ago) {
    var now = new Date();
    var range = [now - ago, now]; // time range is in milliseconds
    //console.log(range[0]);
    
    var prefix = new Name("/ndn/ucla.edu/bms/strathmore/data/demand");
    dataStat = new DataStat(prefix, range);

    var filter = new Exclude([Exclude.ANY, UnsignedIntToArrayBuffer(range[0])]);
    
    var template = new Interest();
    template.childSelector = 0;
    template.interestLifetime = 1000;
    template.exclude = filter;

    ndn.expressInterest(prefix, template, onData, onTimeout);
}

var ndn;
var hub = selectRandomHub();

$(document).ready(function() {
    ndn = new NDN({port:9696, host:hub});
    ndn.onopen = function() { get_data_since(1800000); };
    ndn.connect();
});
