@load base/frameworks/notice

module ServiceVersionAttack;

export {
    #Define a notice type for service version attack detection
    redef enum Notice::Type += {
        Possible_Service_version_Attack_Detected
    };
}

#Keep a count of connections from each IP
global scans: table[addr] of count &default=0;


event connection_state_remove(c: connection)
{
    #Check if the specific connection matches one of the flags.
    if (c$history == "ShADad" ||
        c$history == "ShADadFf" ||
        c$history == "ShADadfF" ||
        c$history == "ShADadFfR" ||
        c$history == "ShADadgFf")    
        {

        #Log the ip and increment the count, if one of the conditions are true.    
        local ip = c$id$orig_h;

        scans[ip] += 1;

        }
}
event zeek_done()
{
    #Check the logged Ips.
    for (ip in scans)
    {
        # Only report the IP after 150 suspicious connections, that 
        #initiates a unusual amount of TCP connections to multiple ports. 
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


