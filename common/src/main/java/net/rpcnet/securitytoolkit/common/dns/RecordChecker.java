package net.rpcnet.securitytoolkit.common.dns;

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

public final class RecordChecker {

    private static final Logger LOGGER = LoggerFactory.getLogger(RecordChecker.class);

    private RecordChecker(){
        //Private utility class constructor
    }

    public static Collection<CAADto> getCAA(String domain){
        return getCAA("%s", domain);
    }

    public static Collection<String> getTXT(String domain){
        return getTXT("%s", domain);
    }
    public static Collection<String> getTXT(String format, String domain){
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

    public static Collection<CAADto> getCAA(String format, String domain){
        String testingDomain = String.format(format, domain);
        final Collection<CAADto> result = new ArrayList<>();

        try {
            final Lookup lookup = new Lookup(testingDomain, Type.CAA);
            lookup.setResolver(new SimpleResolver());
            lookup.setCache(null);
            final Record[] records = lookup.run();
            if (lookup.getResult() == Lookup.SUCCESSFUL) {
                for (Record record : records) {
                    final CAARecord caa = (CAARecord) record;
                    result.add(new CAADto(caa.getValue(), caa.getFlags(), caa.getTag()));
                }
            }
        } catch (UnknownHostException | TextParseException e) {
            LOGGER.error("Error processing the DNS Query: ", e);
        }

        return result;
    }

    public static final class CAADto {

        private final String value;
        private final int flags;
        private final String tag;

        public CAADto(String value, int flags, String tag) {
            this.value = value;
            this.flags = flags;
            this.tag = tag;
        }

        public String getValue() {
            return value;
        }

        public int getFlags() {
            return flags;
        }

        public String getTag() {
            return tag;
        }
    }

}
