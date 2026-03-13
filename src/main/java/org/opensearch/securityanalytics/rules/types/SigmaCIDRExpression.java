/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.types;

import com.cronutils.utils.VisibleForTesting;
import org.opensearch.securityanalytics.rules.exceptions.SigmaTypeError;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SigmaCIDRExpression implements SigmaType {
    private String cidr;
    private boolean ipv6;

    public SigmaCIDRExpression(String cidr) throws SigmaTypeError {
        this.cidr = cidr;

        if (isIPv4AddressValid(this.cidr)) {
            this.ipv6 = false;
        } else if (isIPv6AddressValid(this.cidr)) {
            this.ipv6 = true;
        } else {
            throw new SigmaTypeError("Invalid CIDR expression: " + cidr);
        }
    }

    public String convert() {
        return this.cidr;
    }

    @VisibleForTesting
    public boolean isIpv6() {
        return ipv6;
    }

    private static boolean isIPv4AddressValid(String cidr) {
        if (cidr == null) {
            return false;
        }

        String[] values = cidr.split("/");
        Pattern ipv4Pattern = Pattern
                .compile("(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.){3}([01]?\\d\\d?|2[0-4]\\d|25[0-5])");
        Matcher mm = ipv4Pattern.matcher(values[0]);
        if (!mm.matches()) {
            return false;
        }
        if (values.length >= 2) {
            int prefix = Integer.parseInt(values[1]);
            if ((prefix < 0) || (prefix > 32)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Validates IPv6 addresses including:
     * - Full notation (e.g., 2001:0db8:85a3:0000:0000:8a2e:0370:7334)
     * - Compressed notation (e.g., 2001:db8::1, ::1, ::)
     * - IPv6 CIDR (e.g., 2001:db8::/32, fe80::/10)
     */
    static boolean isIPv6AddressValid(String cidr) {
        if (cidr == null || cidr.isEmpty()) {
            return false;
        }

        String address;
        int prefixLen;

        int slashIdx = cidr.indexOf('/');
        if (slashIdx >= 0) {
            address = cidr.substring(0, slashIdx);
            try {
                prefixLen = Integer.parseInt(cidr.substring(slashIdx + 1));
            } catch (NumberFormatException e) {
                return false;
            }
            if (prefixLen < 0 || prefixLen > 128) {
                return false;
            }
        } else {
            address = cidr;
        }

        // Must contain at least one colon to be IPv6
        if (!address.contains(":")) {
            return false;
        }

        try {
            // Wrap in brackets to avoid ambiguity with scoped addresses
            InetAddress addr = InetAddress.getByName(address);
            return addr instanceof Inet6Address;
        } catch (UnknownHostException e) {
            return false;
        }
    }

    public String getCidr() {
        return cidr;
    }
}
