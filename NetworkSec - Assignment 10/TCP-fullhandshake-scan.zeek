@load base/frameworks/notice

module SYNScan;
#Define the module name
export {
    redef enum Notice::Type += {
        Possible_TCP_Scan_Detected
    };
}
#Initialize a table, to keep track of the flagged ips.
global scans: table[addr] of count &default=0;

event connection_state_remove(c: connection)
{
    #Check if the connection matches the condition
    if (c$history == "ShAR")
    {
        #Log the IP and increment the count, if it does.
        local ip = c$id$orig_h;

        scans[ip] += 1;
        
    }
}

event zeek_done()
{
    #Check the logged Ips.
    for (ip in scans)
    {
        #Report the IP if it has more than 10 or more matching connections, 
        #the IP has made 10 or more TCP connections and imitatly reset the connection. 
        if (scans[ip] >= 10)
        {
            local msg = fmt("IP: %s; Total matching TCP connections: %d",
                            ip, scans[ip]);

            # Write the detection to notice.log
            NOTICE([
                $note=Possible_TCP_Scan_Detected,
                $msg=msg,
                $src=ip
            ]);

            print msg;

        }
    }
}