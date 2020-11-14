package net.rpcnet.securitytoolkit.web.ssl.caa;

import net.rpcnet.securitytoolkit.common.dns.RecordChecker;
import net.rpcnet.securitytoolkit.common.dns.interfaces.CAADto;

import java.util.Collection;
import java.util.stream.Collectors;

public final class DNSCAAChecker {

    private final RecordChecker recordChecker;

    DNSCAAChecker(RecordChecker recordChecker){
        this.recordChecker = recordChecker;
    }

    public Collection<CAAResult> checkDNSCAA(String domain){
        Collection<CAADto> caa = recordChecker.getCAA(domain);
        return caa.stream().map(this::buildCAAResult).collect(Collectors.toList());
    }

    public CAAResult buildCAAResult(CAADto dto){
        return ImmutableCAAResult.builder().flags(dto.getFlags()).tag(dto.getTag()).value(dto.getValue()).build();
    }
}
