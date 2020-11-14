package net.rpcnet.securitytoolkit.common.dns.wrapper;

import net.rpcnet.securitytoolkit.common.dns.interfaces.IDNSResolverWrapper;
import net.rpcnet.securitytoolkit.common.dns.interfaces.ImmutableWrapperCAADto;
import net.rpcnet.securitytoolkit.common.dns.interfaces.WrapperCAADto;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xbill.DNS.CAARecord;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Record;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.TXTRecord;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;

import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collection;

public final class DNSResolverWrapper implements IDNSResolverWrapper {

    private static final Logger LOGGER = LoggerFactory.getLogger(DNSResolverWrapper.class);

    @Override
    public Collection<String> getTXT(String format, String domain){
        String testingDomain = String.format(format, domain);
        final Collection<String> result = new ArrayList<>();

        try {
            final Lookup lookup = new Lookup(testingDomain, Type.TXT);
            lookup.setResolver(new SimpleResolver());
            lookup.setCache(null);
            final Record[] records = lookup.run();
            if (lookup.getResult() == Lookup.SUCCESSFUL) {
                for (Record record : records) {
                    final TXTRecord txt = (TXTRecord) record;
                    result.addAll(txt.getStrings());
                }
            }
        } catch (UnknownHostException | TextParseException e) {
            LOGGER.error("Error processing the DNS Query: ", e);
        }

        return result;
    }

    @Override
    public Collection<WrapperCAADto> getCAA(String format, String domain){
        String testingDomain = String.format(format, domain);
        final Collection<WrapperCAADto> result = new ArrayList<>();

        try {
            final Lookup lookup = new Lookup(testingDomain, Type.CAA);
            lookup.setResolver(new SimpleResolver());
            lookup.setCache(null);
            final Record[] records = lookup.run();
            if (lookup.getResult() == Lookup.SUCCESSFUL) {
                for (Record record : records) {
                    final CAARecord caa = (CAARecord) record;
                    result.add(ImmutableWrapperCAADto.builder().value(caa.getValue()).flags(caa.getFlags()).tag(caa.getTag()).build());
                }
            }
        } catch (UnknownHostException | TextParseException e) {
            LOGGER.error("Error processing the DNS Query: ", e);
        }

        return result;
    }
}
