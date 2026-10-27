@load base/frameworks/notice

module SYNScan;

export {
    redef enum Notice::Type += {
        Possible_TCP_Scan_Detected
    };
}

global scans: table[addr] of count &default=0;

event connection_state_remove(c: connection)
{
    if (c$history == "ShAR")
    {
        local ip = c$id$orig_h;

        scans[ip] += 1;
        
    }
}

event zeek_done()
{
    for (ip in scans)
    {
        if (scans[ip] >= 1)
        {
            local msg = fmt("IP: %s; Total matching TCP connections: %d",
                            ip, scans[ip]);


            NOTICE([
                $note=Possible_TCP_Scan_Detected,
                $msg=msg,
                $src=ip
            ]);

            print msg;

        }
    }
}