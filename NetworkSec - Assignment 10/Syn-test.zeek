@load base/frameworks/notice

module SYNScan;

export {
    redef enum Notice::Type += {
        SYN_Scan_Detected
    };
}

global scans: table[addr] of count &default=0;
global notices: table[addr] of count &default=0;

event connection_state_remove(c: connection)
{
    if (c$history == "ShR" || c$history == "Sr")
    {
        local ip = c$id$orig_h;

        scans[ip] += 1;

        # Only report the IP after 10 suspicious connections
        if (scans[ip] >= 10)
        {
            local msg = fmt("Possible SYN scan from %s; previous Notices: %d",
                            ip, notices[ip]);

            # Write the detection to notice.log
            NOTICE([
                $note=SYN_Scan_Detected,
                $msg=msg,
                $src=ip
            ]);

            print msg;

            notices[ip] += 1;
            scans[ip] = 0;
        }
    }
}