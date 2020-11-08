package net.rpcnet.securitytoolkit.mail.spf;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

public final class SPFParser {

    public static final String SPACE = " ";

    private SPFParser(){
        //Private utility class constructor
    }

    public static Optional<SPFResult> parseSPF(String dnsResponse){

        List<String> spfParameters = Arrays.stream(dnsResponse.split(SPACE)).collect(Collectors.toList());



        return Optional.empty();
    }
}
