# check http sessions and if a source IP is related to three different user-agents or more
# output “xxx.xxx.xxx.xxx is a proxy” where xxx.xxx.xxx.xxx is the source IP

global store: table[addr] of set[string] = {};

event http_header(c: connection, is_orig: bool, name: string, value: string) {
	if (c$id$orig_h !in store){
		store[c$id$orig_h] = set();
		if(c$http?$user_agent){
			add store[c$id$orig_h][to_lower(c$http$user_agent)];
		}
		
	}
	else{
		if(c$http?$user_agent){
			if (to_lower([c$http$user_agent]) !in store[c$id$orig_h]){
				add store[c$id$orig_h][to_lower(c$http$user_agent)];
			}
		}
	}
}

event zeek_done(){
	for (ip in store){
		if (|store[ip]| > 2){
			print fmt("%s is a proxy",ip);
		}
	}
}
