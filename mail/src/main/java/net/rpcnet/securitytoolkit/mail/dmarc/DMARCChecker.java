package net.rpcnet.securitytoolkit.mail.dmarc;

import net.rpcnet.securitytoolkit.common.dns.RecordChecker;

import java.util.Objects;
import java.util.Optional;

public class DMARCChecker {
    private static final String DMARC_FORMAT = "_dmarc.%s";

    private DMARCChecker(){
        //Private utility class constructor
    }

    public static Optional<DMARCResult> getDMARC(String domain){
        String dnsResponse = Objects.requireNonNull(RecordChecker.getTXT(DMARC_FORMAT, domain)).stream().findFirst().orElse(null);

        if(dnsResponse == null || dnsResponse.isEmpty() || dnsResponse.isBlank()){
            return Optional.empty();
        }

        return DMARCParser.parseDMARCResponse(dnsResponse);
    }

}
