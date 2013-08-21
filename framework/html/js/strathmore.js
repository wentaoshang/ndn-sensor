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
    var co_name = co.name;
    //console.log(co_name.to_uri());
    
    var json_text = DataUtils.toString(co.content);
    var json_obj = jQuery.parseJSON(json_text).data;
    
    // Record the data samples
    for (var i = 0; i < json_obj.length; i++) {
	dataStat.x.push(i + dataStat.sample_num);
	dataStat.ts.push(json_obj[i].ts);
	dataStat.y1.push(json_obj[i].vlna);
	dataStat.y2.push(json_obj[i].la / 10);
    }
    
    dataStat.sample_num += json_obj.length;
    
    if (dataStat.sample_num >= 3600) {
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
