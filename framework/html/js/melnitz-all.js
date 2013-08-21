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
    { name: "/ndn/ucla.edu/bms/melnitz/data/1451/electrical/aggregate/power", unit: "kW", lable: "MLNTZ.STUDIO1.DEMAND" },
    { name: "/ndn/ucla.edu/bms/melnitz/data/1451/electrical/aggregate/peak", unit: "kW", lable: "MLNTZ.STUDIO1.PEAK" },
    { name: "/ndn/ucla.edu/bms/melnitz/data/1451/electrical/aggregate/5minavg", unit: "kW", lable: "MLNTZ.STUDIO1.A405" },
    { name: "/ndn/ucla.edu/bms/melnitz/data/1451/electrical/aggregate/10minavg", unit: "kW", lable: "MLNTZ.STUDIO1.A410" },
    { name: "/ndn/ucla.edu/bms/melnitz/data/1451/electrical/aggregate/15minavg", unit: "kW", lable: "MLNTZ.STUDIO1.A415" },
    { name: "/ndn/ucla.edu/bms/melnitz/data/1451/electrical/aggregate/daytot", unit: "kW", lable: "MLNTZ.STUDIO1.A4DC" },
    { name: "/ndn/ucla.edu/bms/melnitz/data/1451/electrical/aggregate/weektot", unit: "kW", lable: "MLNTZ.STUDIO1.C7" },
    { name: "/ndn/ucla.edu/bms/melnitz/data/1451/electrical/aggregate/weekavg", unit: "kW", lable: "MLNTZ.STUDIO1.C7AVG" },
    { name: "/ndn/ucla.edu/bms/melnitz/data/1451/electrical/aggregate/monthtot", unit: "kW", lable: "MLNTZ.STUDIO1.MON" },
    { name: "/ndn/ucla.edu/bms/melnitz/data/1451/electrical/aggregate/voltage", unit: "Volt", lable: "MLNTZ.STUDIO1.VOLTS" },
    { name: "/ndn/ucla.edu/bms/melnitz/data/1451/electrical/aggregate/current", unit: "Ampere", lable: "MLNTZ.STUDIO1.AMPS" },
    // DMR
    { name: "/ndn/ucla.edu/bms/melnitz/data/1451/electrical/panel/DMR/power", unit: "kW", lable: "MLNTZ.PNL.DMR.DEMAND" },
    { name: "/ndn/ucla.edu/bms/melnitz/data/1451/electrical/panel/DMR/peak", unit: "kW", lable: "MLNTZ.PNL.DMR.PEAK"  },
    { name: "/ndn/ucla.edu/bms/melnitz/data/1451/electrical/panel/DMR/voltage", unit: "Volt", lable: "MLNTZ.PNL.DMR.VOLTS"  },
    { name: "/ndn/ucla.edu/bms/melnitz/data/1451/electrical/panel/DMR/current", unit: "Ampere", lable: "MLNTZ.PNL.DMR.AMPS" },
    // AH8
    { name: "/ndn/ucla.edu/bms/melnitz/data/1451/electrical/panel/AH8/power", unit: "kW", lable: "MLNTZ.PNL.AH8.DEMAND" },
    { name: "/ndn/ucla.edu/bms/melnitz/data/1451/electrical/panel/AH8/peak", unit: "kW", lable: "MLNTZ.PNL.AH8.PEAK" },
    { name: "/ndn/ucla.edu/bms/melnitz/data/1451/electrical/panel/AH8/voltage", unit: "Volt", lable: "MLNTZ.PNL.AH8.VOLTS" },
    { name: "/ndn/ucla.edu/bms/melnitz/data/1451/electrical/panel/AH8/current", unit: "Ampere", lable: "MLNTZ.PNL.AH8.AMPS" },
    // AA
    { name: "/ndn/ucla.edu/bms/melnitz/data/1451/electrical/panel/AA/power", unit: "kW", lable: "MLNTZ.PNL.AA.DEMAND" },
    { name: "/ndn/ucla.edu/bms/melnitz/data/1451/electrical/panel/AA/peak", unit: "kW", lable: "MLNTZ.PNL.AA.PEAK" },
    { name: "/ndn/ucla.edu/bms/melnitz/data/1451/electrical/panel/AA/voltage", unit: "Volt", lable: "MLNTZ.PNL.AA.VOLTS" },
    { name: "/ndn/ucla.edu/bms/melnitz/data/1451/electrical/panel/AA/current", unit: "Ampere", lable: "MLNTZ.PNL.AA.AMPS" },
    // K
    { name: "/ndn/ucla.edu/bms/melnitz/data/1451/electrical/panel/K/power", unit: "kW", lable: "MLNTZ.PNL.K.DEMAND" },
    { name: "/ndn/ucla.edu/bms/melnitz/data/1451/electrical/panel/K/peak", unit: "kW", lable: "MLNTZ.PNL.K.PEAK" },
    { name: "/ndn/ucla.edu/bms/melnitz/data/1451/electrical/panel/K/voltage", unit: "Volt", lable: "MLNTZ.PNL.K.VOLTS" },
    { name: "/ndn/ucla.edu/bms/melnitz/data/1451/electrical/panel/K/current", unit: "Ampere", lable: "MLNTZ.PNL.K.AMPS" },
    // J
    { name: "/ndn/ucla.edu/bms/melnitz/data/1451/electrical/panel/J/power", unit: "kW", lable: "MLNTZ.PNL.J.DEMAND" },
    { name: "/ndn/ucla.edu/bms/melnitz/data/1451/electrical/panel/J/peak", unit: "kW", lable: "MLNTZ.PNL.J.PEAK" },
    { name: "/ndn/ucla.edu/bms/melnitz/data/1451/electrical/panel/J/voltage", unit: "Volt", lable: "MLNTZ.PNL.J.VOLTS" },
    { name: "/ndn/ucla.edu/bms/melnitz/data/1451/electrical/panel/J/current", unit: "Ampere", lable: "MLNTZ.PNL.J.AMPS" }
    ];

function draw_table() {
    for (var i = 0; i < data_points.length; i++) {
	var name = data_points[i].name;
	var bacnet_name = data_points[i].lable;
	var ts_id = bacnet_name.replace(/\./g, '_') + '_ts';
	var val_id = bacnet_name.replace(/\./g, '_') + '_val';
	var prefix = new Name(name);
	var unit = data_points[i].unit;

	$("#list").append( '<tr><td style="width:40%">' + bacnet_name + '</td><td style="width:20%" id="' + ts_id + '">' 
			   + '</td><td style="width:30%" id="' + val_id + '"></td><td style="width:10%">' + unit + '</td></tr>' );
    }
}

function get_all_data() {
    $("#loader").fadeOut(50);
    $("article").fadeIn(100);

    draw_table();

    var now = new Date();
    var start = now - 60000; // in milliseconds
    console.log('Fetch data starting from ' + new Date(start));
    
    var filter = new Exclude([Exclude.ANY, UnsignedIntToArrayBuffer(start)]);
    
    var template = new Interest();
    template.childSelector = 0;
    template.interestLifetime = 1000;
    template.exclude = filter;
    
    for (var i = 0; i < data_points.length; i++) {
	(function () {
	    var index = i;
	    var name = data_points[index].name;
	    var bacnet_name = data_points[index].lable;
	    var prefix = new Name(name);
	    var unit = data_points[index].unit;


	    var display_data = function (obj) {
		//console.log('Trying to show data for ' + bacnet_name);

		var ts = (new Date(obj.ts)).toLocaleTimeString();
		var val = obj.val;

		var ts_id = bacnet_name.replace(/\./g, '_') + '_ts';
		var val_id = bacnet_name.replace(/\./g, '_') + '_val';

		$("#" + ts_id).text(ts);
		$("#" + val_id).text(val);
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

		//setTimeout(function () {ndn.expressInterest(prefix, template, onData, onTimeout); }, 2000);
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

		var template = new Interest();
		template.interestLifetime = 8000;

		//console.log('Fetch sym key: ' + sym_key_name.to_uri());
		ndn.expressInterest(sym_key_name, null, onKeyData, onKeyTimeout);
	    };

	    var onData = function (inst, co) {
		console.log(co.name.to_uri());
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
	}) ();
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
