package net.rpcnet.securitytoolkit.web.ssl.caa;

import net.rpcnet.securitytoolkit.common.dns.RecordChecker;

import java.util.Collection;
import java.util.stream.Collectors;

public final class DNSCAAChecker {

    private DNSCAAChecker(){
        //Private utility class constructor
    }

    public static Collection<CAAResult> checkDNSCAA(String domain){
        Collection<RecordChecker.CAADto> caa = RecordChecker.getCAA(domain);
        return caa.stream().map(DNSCAAChecker::buildCAAResult).collect(Collectors.toList());
    }

    public static CAAResult buildCAAResult(RecordChecker.CAADto dto){
        return ImmutableCAAResult.builder().flags(dto.getFlags()).tag(dto.getTag()).value(dto.getValue()).build();
    }
}
