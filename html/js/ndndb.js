var DataStat = function DataStat (prfx) {
  this.prefix = prfx; // prefix for the data namespace
  this.sample_num = 0; // total number of collected data
};

var onData = function (inst, data) {
  fetchDecryptionKey(data);
};

var iv_len = 16;
var key_ts_len = 8;

var fetchDecryptionKey = function (data) {
  var key_ts = data.content.subarray(0, key_ts_len);
  
  var onKeyData = function (inst, key_data) {
    var ciphertext = DataUtils.toHex(key_data.content);
    var rsa = new RSAKey();
    rsa.readPrivateKeyFromPEMString(usrDefaultKey.privatePem);
    var sym_key = rsa.decrypt(ciphertext);
    processData(data, sym_key);
  };
  
  var sym_key_name = new Name('/ndn/ucla.edu/bms/melnitz/kds').append(key_ts).append(usrKeyID);
  var template = new Interest();
  template.interestLifetime = 4000;
  template.setMustBeFresh(false);

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
  
  var json_text = p1.toString(CryptoJS.enc.Utf8) + p2.toString(CryptoJS.enc.Utf8);
  var json_obj = jQuery.parseJSON(json_text);

  dataStat.sample_num++;

  if (dataStat.sample_num >= max_data_num) {
    $("#result").append("Imported " + dataStat.sample_num + " data points.")
      .append("<br/>");
    $("#query").val("SELECT * FROM bms;");
    $("#run").attr("disabled", false);
  } else {
    // Insert data into db
    var stmt = db.prepare("INSERT INTO bms VALUES (?, ?, ?, ?, ?, ?);");
    stmt.bind(["melnitz", "studio1", "total", "demand", json_obj.ts, json_obj.val]);
    stmt.step();
    stmt.free();

    // Send interest for the next content object
    var tpos = data_name.components.length - 1;
    var ts = data_name.components[tpos];
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
  $("#ndndb").hide();
  $('#error').append("<p>Currently I'm connected to " + hub + ".</p>");
  $("#error").fadeIn(100);
};

var dataStat;

function loadData() {
  $("#result").append("Loading data...").append("<br/>");

  var name = new Name(data_points[data_index].name);
  dataStat = new DataStat(name);

  var template = new Interest();
  template.childSelector = 1;
  template.setMustBeFresh(true);
  template.interestLifetime = 4000;
  
  face.expressInterest(name, template, onData, onTimeout);
}

function executeQuery () {
  var query = $("#query").val().toUpperCase();
  if (query == "" || query == null) {
    $("#result").append("Error: empty query!").append("<br/>");
    return;
  }

  $("#result").append("Execute query: <strong>" + query + "</strong>").append("<br/>");
  var stmt;
  try {
    stmt = db.prepare(query);
  } catch (e) {
    $("#result").append("<font color='red'>Fatal: " + e.message + "</font>").append("<br/>");
    return;
  }
  stmt.step();
  var colName = stmt.getColumnNames();
  var tb = "Result:<br/><table><tr>";
  for (var i = 0; i < colName.length; i++)
  {
    tb += "<td>" + colName[i] + "</td>";
  }
  tb += "</tr>";
  do {
    var res = stmt.get();
    tb += "<tr>";
    for (var i = 0; i < res.length; i++)
    {
      tb += "<td>" + res[i] + "</td>"
    }
    tb += "</tr>";
  } while (stmt.step())
  tb += "</table><br/>";
  $("#result").append(tb);
}

var db;
var face;
var hub = "borges.metwi.ucla.edu";
var data_index = 0;
var max_data_num = 200;
var schema = ["BUILDING", "ROOM", "PANEL", "TYPE", "TIMESTAMP", "VALUE"];

$(document).ready(function () {
  face = new Face({port:9696, host:hub});
  db = new SQL.Database();
  db.run("CREATE TABLE bms (" + schema.toString() + ");");
  $("#loader").fadeOut(50);
  $("#ndndb").fadeIn(100);
  loadData();
});
