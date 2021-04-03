global ss:table[addr] of set[string];
event http_agent(c: connection, hlist: mime_header_list)
{
    local s:string=c$http$user_agent;
    local a:addr=c$id$orig_h;
    add ss[a][to_lower(s)];
}

event zeek_done()
{	
	for (ip in ss)
	{
		if(|ss[ip]|>=3)
			print ip," is a proxy";
	}
}
