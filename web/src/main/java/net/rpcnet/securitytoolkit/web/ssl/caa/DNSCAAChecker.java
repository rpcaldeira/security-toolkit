package net.rpcnet.securitytoolkit.web.ssl.caa;

import net.rpcnet.securitytoolkit.common.dns.RecordChecker;

import java.util.Collection;

public final class DNSCAAChecker {

    private DNSCAAChecker(){
        //Private utility class constructor
    }

    public static String checkDNSCAA(String domain){
        Collection<String> caa = RecordChecker.getCAA(domain);
        return "";
    }

}
