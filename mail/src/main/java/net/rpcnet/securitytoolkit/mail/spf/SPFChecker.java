package net.rpcnet.securitytoolkit.mail.spf;

import net.rpcnet.securitytoolkit.common.dns.RecordChecker;

import java.util.Collection;

public class SPFChecker {

    public static final String SPF = "spf";

    private SPFChecker(){
        //Private utility class constructor
    }

    public static String getSPF(String domain){
        Collection<String> txtRecords = RecordChecker.getTXT(domain);
        return txtRecords.stream().filter(str -> str.contains(SPF)).findAny().orElse(null);
    }

}
