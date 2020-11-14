package net.rpcnet.securitytoolkit.mail.spf;

import net.rpcnet.securitytoolkit.common.dns.RecordChecker;

import java.util.Optional;

public class SPFChecker {

    private final RecordChecker recordChecker;

    public SPFChecker(){
        this.recordChecker = new RecordChecker();
    }

    SPFChecker(RecordChecker recordChecker){
        this.recordChecker = recordChecker;
    }

    public Optional<SPFResult> getSPF(String domain){
        Optional<String> dnsResponse = recordChecker.getTXT(domain).stream()
                .filter(str -> str.contains(RecordChecker.SPF))
                .findAny();

        if(dnsResponse.isEmpty()){
            return Optional.empty();
        }

        return SPFParser.parseSPF(dnsResponse.get());
    }

}
