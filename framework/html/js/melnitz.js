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
	
var AsyncGetClosure = function AsyncGetClosure(prfx, range) {
    this.version = null; // uint8array for the version code
    this.prefix = prfx; // prefix for the namespace (excluding the version code)
    this.data_prefix = null;
    this.range = range; // array of two integers [start, end], the time range within which we want to fetch the data
			
    this.x = [];
    this.y1 = [];
    this.y2 = [];
    this.sample_num = 0;
};
		
var display_time = function (container) {
    var now = dataStat.range[1];
			
    container.innerHTML = '<table style="width: 100%; margin-top: -12px"><tr>' + 
    '<td width="20%">' + (new Date(now - 600000)).toTimeString().substr(0, 8) + '</td>' + 
    '<td width="20%">' + (new Date(now - 480000)).toTimeString().substr(0, 8) + '</td>' + 
    '<td width="20%">' + (new Date(now - 360000)).toTimeString().substr(0, 8) + '</td>' +
    '<td width="20%">' + (new Date(now - 240000)).toTimeString().substr(0, 8) + '</td>' +
    '<td width="15%">' + (new Date(now - 120000)).toTimeString().substr(0, 8) + '</td>' +
    '<td width="5%" align="right">' + (new Date(now)).toTimeString().substr(0, 8) + '</td></tr></table>';
};
		
var display_data = function () {
    $("#loader").fadeOut(50);
    $("article").fadeIn(100);
			
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

var onData = function (inst, co) {
    var co_name = co.name;
    //console.log(co_name.to_uri());
    
    if (dataStat.version == null) {
	var vpos = dataStat.prefix.components.length;
	dataStat.version = co_name.components[vpos];
	//console.log(dataStat.version);
	
	dataStat.data_prefix = new Name(dataStat.prefix).append(dataStat.version).append('index');
	//console.log(dataStat.data_prefix.to_uri());
	//console.log(dataStat.prefix.to_uri());
	
	// Send interest to get the latest content.
	var filter = new Exclude([Exclude.ANY, UnsignedIntToArrayBuffer(dataStat.range[0])]);
	
	var template = new Interest();
	template.childSelector = 0;
	template.answerOriginKind = 0;
	template.interestLifetime = 1000;
	template.exclude = filter;
	
	ndn.expressInterest(dataStat.data_prefix, template, onData, onTimeout);
	return;
    }
    
    var json_text = DataUtils.toString(co.content);
    var json_obj = jQuery.parseJSON(json_text).data;
    
    // Record the data samples
    for (var i = 0; i < json_obj.length; i++) {
	dataStat.x.push(i + dataStat.sample_num);
	dataStat.y1.push(json_obj[i].pw);
    }
    
    dataStat.sample_num += json_obj.length;
    
    if (dataStat.sample_num >= 600) {
	// We have collected enough samples. Display in time series
	display_data();
    } else {
	// Send interest for the next content object
	var tpos = co_name.components.length - 1;
	var ts = co_name.components[tpos];
	//console.log(ts);
				
	var filter = new Exclude([Exclude.ANY, ts]);
				
	var template = new Interest();
	template.childSelector = 0;
	template.interestLifetime = 1000;
	template.exclude = filter;
				
	ndn.expressInterest(dataStat.data_prefix, template, onData, onTimeout);
    }
};

var onTimeout = function (inst) {
    console.log("Interest time out.");
    console.log("Interest name is " + inst.name.to_uri());
            
    if (dataStat.sample_num > 0) {
	// Display what we have up to now
	display_data();
    } else {
	$("#loader").hide();
	$("#error").fadeIn(100);
    }
};

var dataStat;
function get_data_since(ago) {
    var now = new Date();
    var range = [now - ago, now]; // time range is in milliseconds
    //console.log(range[0]);
    
    // Template interest to get the latest content.
    var template = new Interest();
    template.childSelector = 1;
    template.answerOriginKind = 0;
    template.interestLifetime = 1000;
    
    var name = new Name("/ndn/ucla.edu/apps/cps/melnitz/TV1/PanelJ");
    dataStat = new AsyncGetClosure(name, range);
    
    ndn.expressInterest(name, template, onData, onTimeout);
}

// Calls to get the content data.
function begin() {
    get_data_since(600000);
}

var ndn;

$(document).ready(function() {
	$("#all").fadeIn(1000);
	
	var openHandle = function() { begin() };
	ndn = new NDN({port:9696, host:"ndnucla-staging.dyndns.org", onopen:openHandle});
	ndn.connect();
    });
