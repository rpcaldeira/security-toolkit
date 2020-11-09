package net.rpcnet.securitytoolkit.mail.spf;

import org.immutables.value.Value;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Value.Immutable
public abstract class SPFResult {

    private static final String VERSION_KEY = "v=spf";
    private static final String MAIL_EXCHANGE_KEY = "mx";
    private static final String A_KEY = "a";
    private static final String ALL_KEY = "all";
    private static final String INCLUDE_KEY = "include:";
    private static final String IP4_KEY = "ip4:";
    private static final String IP6_KEY = "ip6:";

    public abstract Optional<Integer> getVersion();
    public abstract Optional<SPFQualifier> getMailExchangeQualifier();
    public abstract Optional<SPFQualifier> getAQualifier();
    public abstract List<SPFElement> getIp4Records();
    public abstract List<SPFElement> getIp6Records();
    public abstract Optional<SPFQualifier> getAllQualifier();
    public abstract List<SPFElement> getIncludeRecords();

    @Override
    public String toString() {
        List<String> list = new ArrayList<>();

        getMailExchangeQualifier().ifPresent(s -> list.add(s.getSign() + MAIL_EXCHANGE_KEY));
        getVersion().ifPresent(s -> list.add(VERSION_KEY + s));
        getAQualifier().ifPresent(s -> list.add(s.getSign() + A_KEY));
        getAllQualifier().ifPresent(s -> list.add(s.getSign() + ALL_KEY));
        getIncludeRecords().forEach(s -> list.add(s.getQualifier().getSign() + INCLUDE_KEY + s.getValue()));
        getIp4Records().forEach(s -> list.add(s.getQualifier().getSign() + INCLUDE_KEY + s.getValue()));
        getIp6Records().forEach(s -> list.add(s.getQualifier().getSign() + INCLUDE_KEY + s.getValue()));

        return String.join(" ", list);
    }
}
