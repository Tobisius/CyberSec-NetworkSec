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
    # Count TCP connections matching the selected handshake histories
    if (c$history == "ShADad" ||
        c$history == "ShADadFf" ||
        c$history == "ShADadfF" ||
        c$history == "ShADadFfR" ||
        c$history == "ShADadgFf")
    {
        local ip = c$id$orig_h;

        scans[ip] += 1;
    }
}

event zeek_done()
{
    for (ip in scans)
    {
        if (scans[ip] >= 10)
        {
            local msg = fmt("IP: %s; Total matching TCP connections: %d",
                            ip, scans[ip]);

            print msg;

            NOTICE([
                $note=SYN_Scan_Detected,
                $msg=msg,
                $src=ip
            ]);
        }
    }
}