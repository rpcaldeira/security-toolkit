package net.rpcnet.securitytoolkit.common.dns;

import net.rpcnet.securitytoolkit.common.dns.interfaces.CAADto;
import net.rpcnet.securitytoolkit.common.dns.interfaces.IDNSResolverWrapper;
import net.rpcnet.securitytoolkit.common.dns.interfaces.ImmutableCAADto;
import net.rpcnet.securitytoolkit.common.dns.interfaces.WrapperCAADto;
import net.rpcnet.securitytoolkit.common.dns.wrapper.DNSResolverWrapper;

import java.util.Collection;
import java.util.stream.Collectors;

public final class RecordChecker {

    public static final String SPF = "spf";
    private final IDNSResolverWrapper dnsResolverWrapper;

    public RecordChecker(){
        this.dnsResolverWrapper = new DNSResolverWrapper();
    }

    public Collection<CAADto> getCAA(String domain){
        return getCAA("%s", domain);
    }
    public Collection<String> getTXT(String domain){
        return getTXT("%s", domain);
    }
    public Collection<String> getTXT(String format, String domain){
        return dnsResolverWrapper.getTXT(format, domain);
    }

    public Collection<CAADto> getCAA(String format, String domain){
        Collection<WrapperCAADto> caaDtoCollection = dnsResolverWrapper.getCAA(format, domain);
        return caaDtoCollection.stream()
                .map(caa -> ImmutableCAADto.builder().value(caa.getValue()).flags(caa.getFlags()).tag(caa.getTag()).build())
                .collect(Collectors.toList());
    }

}
