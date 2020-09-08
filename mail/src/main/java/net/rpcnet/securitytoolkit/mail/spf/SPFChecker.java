package net.rpcnet.securitytoolkit.mail.spf;

import net.rpcnet.securitytoolkit.common.dns.TXTRecordChecker;

import java.util.Collection;

public class SPFChecker {

    public static final String SPF = "spf";

    public static String getSPF(String domain){
        Collection<String> txtRecords = TXTRecordChecker.getTXT(domain);
        return txtRecords.stream().filter(str -> str.contains(SPF)).findAny().orElse(null);
    }

}
