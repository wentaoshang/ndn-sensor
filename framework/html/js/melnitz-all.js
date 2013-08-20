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
}

var iv_len = 16;
var key_ts_len = 8;

var onTimeout = function (inst) {
    console.log("Interest timeout: " + inst.name.to_uri());
};

var data_points = [
    // studio1
    { name: "/ndn/ucla.edu/bms/melnitz/data/1451/electrical/aggregate/power", unit: "kW" },
    { name: "/ndn/ucla.edu/bms/melnitz/data/1451/electrical/aggregate/power/peak", unit: "kW" },
    { name: "/ndn/ucla.edu/bms/melnitz/data/1451/electrical/aggregate/power/5minavg", unit: "kW" },
    { name: "/ndn/ucla.edu/bms/melnitz/data/1451/electrical/aggregate/power/10minavg", unit: "kW" },
    { name: "/ndn/ucla.edu/bms/melnitz/data/1451/electrical/aggregate/power/15minavg", unit: "kW" },
    { name: "/ndn/ucla.edu/bms/melnitz/data/1451/electrical/aggregate/power/daytot", unit: "kW" },
    { name: "/ndn/ucla.edu/bms/melnitz/data/1451/electrical/aggregate/power/weektot", unit: "kW" },
    { name: "/ndn/ucla.edu/bms/melnitz/data/1451/electrical/aggregate/power/weekavg", unit: "kW" },
    { name: "/ndn/ucla.edu/bms/melnitz/data/1451/electrical/aggregate/power/monthtot", unit: "kW" },
    { name: "/ndn/ucla.edu/bms/melnitz/data/1451/electrical/aggregate/voltage", unit: "Volt" },
    { name: "/ndn/ucla.edu/bms/melnitz/data/1451/electrical/aggregate/current", unit: "Ampere" },
    // DMR
    { name: "/ndn/ucla.edu/bms/melnitz/data/1451/electrical/panel/DMR/power", unit: "kW" },
    { name: "/ndn/ucla.edu/bms/melnitz/data/1451/electrical/panel/DMR/power/peak", unit: "kW" },
    { name: "/ndn/ucla.edu/bms/melnitz/data/1451/electrical/panel/DMR/voltage", unit: "Volt" },
    { name: "/ndn/ucla.edu/bms/melnitz/data/1451/electrical/panel/DMR/current", unit: "Ampere" },
    // AH8
    { name: "/ndn/ucla.edu/bms/melnitz/data/1451/electrical/panel/AH8/power", unit: "kW" },
    { name: "/ndn/ucla.edu/bms/melnitz/data/1451/electrical/panel/AH8/power/peak", unit: "kW" },
    { name: "/ndn/ucla.edu/bms/melnitz/data/1451/electrical/panel/AH8/voltage", unit: "Volt" },
    { name: "/ndn/ucla.edu/bms/melnitz/data/1451/electrical/panel/AH8/current", unit: "Ampere" },
    // AA
    { name: "/ndn/ucla.edu/bms/melnitz/data/1451/electrical/panel/AA/power", unit: "kW" },
    { name: "/ndn/ucla.edu/bms/melnitz/data/1451/electrical/panel/AA/power/peak", unit: "kW" },
    { name: "/ndn/ucla.edu/bms/melnitz/data/1451/electrical/panel/AA/voltage", unit: "Volt" },
    { name: "/ndn/ucla.edu/bms/melnitz/data/1451/electrical/panel/AA/current", unit: "Ampere" },
    // K
    { name: "/ndn/ucla.edu/bms/melnitz/data/1451/electrical/panel/K/power", unit: "kW" },
    { name: "/ndn/ucla.edu/bms/melnitz/data/1451/electrical/panel/K/power/peak", unit: "kW" },
    { name: "/ndn/ucla.edu/bms/melnitz/data/1451/electrical/panel/K/voltage", unit: "Volt" },
    { name: "/ndn/ucla.edu/bms/melnitz/data/1451/electrical/panel/K/current", unit: "Ampere" },
    // J
    { name: "/ndn/ucla.edu/bms/melnitz/data/1451/electrical/panel/J/power", unit: "kW" },
    { name: "/ndn/ucla.edu/bms/melnitz/data/1451/electrical/panel/J/power/peak", unit: "kW" },
    { name: "/ndn/ucla.edu/bms/melnitz/data/1451/electrical/panel/J/voltage", unit: "Volt" },
    { name: "/ndn/ucla.edu/bms/melnitz/data/1451/electrical/panel/J/current", unit: "Ampere" }
    ];

function get_all_data() {
    $("#loader").fadeOut(50);
    $("article").fadeIn(100);

    var now = new Date();
    var start = now - 60000 // in milliseconds
    
    var filter = new Exclude([Exclude.ANY, UnsignedIntToArrayBuffer(start)]);
    
    var template = new Interest();
    template.childSelector = 0;
    template.interestLifetime = 1000;
    template.exclude = filter;
    
    for (var i = 0; i < data_points.length; i++) {
	function () {
	    var index = i;
	    var name = data_points[index].name;
	    var prefix = new Name(name);
	    var unit = data_points[index].unit;


	    var display_data = function (obj) {
		var ts = (new Date(obj.ts)).toLocaleTimeString();
		var val = obj.val;

		$("#list").append( '<tr><td style="width:60%">' + name + '</td><td style="width:15%">' + ts 
				   + '</td><td style="width:15%">' + val + '</td><td style="width:10%">' + unit + '</td></tr>' );

	    };

	    var processData = function (co, sym_key) {
		var co_name = co.name;
		//console.log(co.name.to_uri());

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

		display_data(json_obj);

		// Send interest for the next content object
		var tpos = co_name.components.length - 1;
		var ts = co_name.components[tpos];
		//console.log(ts);

		var filter = new Exclude([Exclude.ANY, ts]);

		var template = new Interest();
		template.childSelector = 0;
		template.interestLifetime = 1000;
		template.exclude = filter;

		//ndn.expressInterest(dataStat.prefix, template, onData, onTimeout);
	    };

	    var fetchDecryptionKey = function (data_co) {
		var key_ts = data_co.content.subarray(0, key_ts_len);

		var onKeyData = function (inst, key_co) {
		    CpsMelnitzPolicy.verify(ndn, key_co, function (result) {
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

		var onKeyTimeout = function (inst) {
		    console.log('Interest timeout when fetching decryption key:');
		    console.log(inst.name.to_uri());
		};
		
		var sym_key_name = new Name('/ndn/ucla.edu/bms/melnitz/kds').append(key_ts).appendKeyID(ndn.getDefaultKey());
		//console.log('Fetch sym key: ' + sym_key_name.to_uri());
		ndn.expressInterest(sym_key_name, null, onKeyData, onKeyTimeout);
	    };

	    var onData = function (inst, co) {
		//console.log(co.name.to_uri());
		CpsMelnitzPolicy.verify(ndn, co, function (result) {
			if (result == VerifyResult.SUCCESS) {
			    fetchDecryptionKey(co);
			} else if (result == VerifyResult.FAILURE)
			    console.log('Data verification failed.');
			else if (result == VerifyResult.TIMEOUT)
			    console.log('Data verification failed due to timeout.');
		    });
	    };

	    ndn.expressInterest(prefix, template, onData, onTimeout);
	} ();
    }
}

var ndn;
var hub = 'localhost';

$(document).ready(function() {
    $("#all").fadeIn(1000);
    
    ndn = new NDN({port:9696, host:hub});
    ndn.onopen = function() { get_all_data(); };
    ndn.connect();
});
