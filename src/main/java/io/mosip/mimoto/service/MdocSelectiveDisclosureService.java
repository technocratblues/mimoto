package io.mosip.mimoto.service;

import java.util.Collection;

public interface MdocSelectiveDisclosureService {

    /**
     * Filters an mdoc credential string (base64url or standard base64 CBOR) to disclose
     * only the selected/requested claims. Preserves raw Tag 24 IssuerSignedItemBytes
     * and issuerAuth untouched for cryptographic verification.
     *
     * @param mdocBase64Url  base64url/base64 encoded CBOR mdoc string
     * @param selectedClaims collection of selected claim paths or element identifiers
     *                       (e.g. "given_name", "org.iso.18013.5.1.given_name", "$.given_name")
     * @return filtered mdoc string in base64url format
     */
    String filterMdoc(String mdocBase64Url, Collection<String> selectedClaims);
}
