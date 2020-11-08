package net.rpcnet.securitytoolkit.mail.spf;

import net.rpcnet.securitytoolkit.common.dns.RecordChecker;

import java.util.Optional;

public class SPFChecker {

    public static final String SPF = "spf";

    private SPFChecker(){
        //Private utility class constructor
    }

    public static Optional<SPFResult> getSPF(String domain){
        String dnsResponse = RecordChecker.getTXT(domain).stream()
                .filter(str -> str.contains(SPF))
                .findAny()
                .orElse(null);

        return SPFParser.parseSPF(dnsResponse);
    }

}
