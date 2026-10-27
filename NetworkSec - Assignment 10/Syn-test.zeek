@load base/frameworks/notice

module SYNScan;

export {
    redef enum Notice::Type += {
        SYN_Scan_Detected
    };
}

global scans: table[addr] of count &default=0;

event connection_state_remove(c: connection)
{
    if (c$history == "ShR" || c$history == "Sr")
    {
        local ip = c$id$orig_h;

        scans[ip] += 1;
    }
}    

event zeek_done()
{
    for (ip in scans)
    {
        # Only report the IP after 10 suspicious connections
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