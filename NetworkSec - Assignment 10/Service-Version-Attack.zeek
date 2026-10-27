@load base/frameworks/notice

module ServiceVersionAttack;

export {
    redef enum Notice::Type += {
        Possible_Service_version_Attack_Detected
    };
}

global scans: table[addr] of count &default=0;


event connection_state_remove(c: connection)
{
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
        # Only report the IP after 15 suspicious connections
            if (scans[ip] >= 150)
            {
                local msg = fmt("Possible service version attack from %s; total matching connections: %d",
                                ip, scans[ip]);
                # Write the detection to notice.log
            NOTICE([
                $note=Possible_Service_version_Attack_Detected,
                $msg=msg,
                $src=ip
            ]);

            print msg;

            }
        }
        
}        


