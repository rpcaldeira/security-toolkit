package net.rpcnet.securitytoolkit.mail.dmarc;

import net.rpcnet.securitytoolkit.common.dns.TXTRecordChecker;

import java.util.Objects;

public class DMARCChecker {
    private static final String DMARC_FORMAT = "_dmarc.%s";

    private DMARCChecker(){
        //Private utility class constructor
    }

    public static String getDMARC(String domain){
        return Objects.requireNonNull(TXTRecordChecker.getTXT(DMARC_FORMAT, domain)).stream()
                .findFirst()
                .orElse(null);
    }

}
