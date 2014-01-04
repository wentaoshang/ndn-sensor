var CpsStrathmorePolicy = new IdentityPolicy(
    // anchors
    [
    // KSK
	{ key_name: new Name("/ndn/ucla.edu/bms/strathmore/%C1.M.K%00%A4%B3%85%8F%40%A7%A1%5E%A6%5BB%14jl%60%97L%B9p.%DAE.E%BF%5CZ%FAE%29%B6%D4"), 
	  namespace: new Name("/ndn/ucla.edu/bms/strathmore"),
	  key: Key.createFromPEM({ pub: '-----BEGIN PUBLIC KEY-----\n' + 
				   'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCtIiqAVoWPP1trON42EstRuETX\n' +
				   'hnK3Sc//HwI+phswrRP+gnDmBFoSQB+J6A0Qeeb8EOMoeEe7qswzGMXNSLo4B7Pg\n' +
				   'PU7v2Gsvtnw8VnCMCoXhgnE7oYU5jUCzDnkEa4gNgrsGX7ViCso2d8eUq1JI2DoP\n' + 
				   'PblAYkk4Zzdfb4SStwIDAQAB\n' +
				   '-----END PUBLIC KEY-----' }) }
    ],
    // rules
    [
	// rule for 'data' sub-namespace
	{ key_pat: new RegExp("^(/ndn/ucla.edu/bms/strathmore/data)/%FD[^/]+/%C1.M.K[^/]+$"), 
	  key_pat_ext: "$1", 
	  data_pat: new RegExp("^(/ndn/ucla.edu/bms/strathmore/data(?:/[^/]+)*)$"), 
	  data_pat_ext: "$1" },

	// rule for 'kds' sub-namespace
	{ key_pat: new RegExp("^(/ndn/ucla.edu/bms/strathmore/kds)/%FD[^/]+/%C1.M.K[^/]+$"), 
	  key_pat_ext: "$1", 
	  data_pat: new RegExp("^(/ndn/ucla.edu/bms/strathmore/kds(?:/[^/]+)*)$"), 
	  data_pat_ext: "$1" }
    ]
);
