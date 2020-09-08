package net.rpcnet.securitytoolkit.common.dns;

import org.xbill.DNS.Lookup;
import org.xbill.DNS.Record;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.TXTRecord;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;

import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;

public class TXTRecordChecker {

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
                    for (Iterator<String> iterator = txt.getStrings().iterator(); iterator.hasNext();) {
                        result.add(iterator.next());
                    }
                }
            }
        } catch (UnknownHostException | TextParseException e) {
            e.printStackTrace();
        }

        return result;
    }
}
