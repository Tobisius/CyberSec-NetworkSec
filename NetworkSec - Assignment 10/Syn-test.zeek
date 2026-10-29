@load base/frameworks/notice

#Define the module name
module SYNScan;

#Define a notice type for SYN scan detection
export {
    redef enum Notice::Type += {
        SYN_Scan_Detected
    };
}

#Initialize a table, to keep track of the flagged ips.
global scans: table[addr] of count &default=0;

event connection_state_remove(c: connection)
{
    #Check if the specific connection matches one of the two flags
    if (c$history == "ShR" || c$history == "Sr")
    {
        #If it matches, log the ip and increment the count.
        local ip = c$id$orig_h;

        scans[ip] += 1;
    }
}    

event zeek_done()
{
    #Check the the IPs, that are logged.
    for (ip in scans)
    {
        #Report the IP if it has more than 10 matching connections, that 
        #initiates a TCP connection and immediately resets the connection.
        if (scans[ip] >= 10)
        {
            local msg = fmt("Possible SYN scan from %s; total matches: %d",
                            ip, scans[ip]);

            # Write the detection to notice.log
            NOTICE([
                $note=SYN_Scan_Detected,
                $msg=msg,
                $src=ip
            ]);
            print msg;
        }
    }
}