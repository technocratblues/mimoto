package io.mosip.mimoto.service.impl;

import co.nstant.in.cbor.CborDecoder;
import co.nstant.in.cbor.CborEncoder;
import co.nstant.in.cbor.model.Array;
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.Map;
import co.nstant.in.cbor.model.UnicodeString;
import co.nstant.in.cbor.model.UnsignedInteger;
import org.junit.Before;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

import static org.junit.Assert.*;

public class MdocSelectiveDisclosureServiceTest {

    private MdocSelectiveDisclosureServiceImpl service;

    @Before
    public void setUp() {
        service = new MdocSelectiveDisclosureServiceImpl();
    }

    private byte[] encodeItem(int digestId, String elementId, String value) throws Exception {
        Map item = new Map();
        item.put(new UnicodeString("digestID"), new UnsignedInteger(digestId));
        item.put(new UnicodeString("random"), new ByteString(new byte[]{1, 2, 3, 4}));
        item.put(new UnicodeString("elementIdentifier"), new UnicodeString(elementId));
        item.put(new UnicodeString("elementValue"), new UnicodeString(value));

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        new CborEncoder(baos).encode(item);
        return baos.toByteArray();
    }

    private String buildSampleMdoc(byte[] item1Bytes, byte[] item2Bytes) throws Exception {
        ByteString taggedItem1 = new ByteString(item1Bytes);
        taggedItem1.setTag(24);
        ByteString taggedItem2 = new ByteString(item2Bytes);
        taggedItem2.setTag(24);

        Array itemsArray = new Array();
        itemsArray.add(taggedItem1);
        itemsArray.add(taggedItem2);

        Map nameSpaces = new Map();
        nameSpaces.put(new UnicodeString("org.iso.18013.5.1"), itemsArray);

        Map issuerSigned = new Map();
        issuerSigned.put(new UnicodeString("nameSpaces"), nameSpaces);
        issuerSigned.put(new UnicodeString("issuerAuth"), new ByteString(new byte[]{99, 98, 97}));

        Map document = new Map();
        document.put(new UnicodeString("docType"), new UnicodeString("org.iso.18013.5.1.mDL"));
        document.put(new UnicodeString("issuerSigned"), issuerSigned);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        new CborEncoder(baos).encode(document);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(baos.toByteArray());
    }

    @Test
    public void testSelectiveDisclosureRetainsOnlyRequestedClaimAndPreservesRawBytes() throws Exception {
        byte[] item1Bytes = encodeItem(0, "given_name", "Alice");
        byte[] item2Bytes = encodeItem(1, "family_name", "Smith");
        String originalMdoc = buildSampleMdoc(item1Bytes, item2Bytes);

        String filteredMdoc = service.filterMdoc(originalMdoc, List.of("given_name"));
        assertNotNull(filteredMdoc);

        byte[] decodedBytes = Base64.getUrlDecoder().decode(filteredMdoc);
        List<DataItem> items = new CborDecoder(new ByteArrayInputStream(decodedBytes)).decode();
        Map doc = (Map) items.get(0);
        Map issuerSigned = (Map) doc.get(new UnicodeString("issuerSigned"));
        Map nameSpaces = (Map) issuerSigned.get(new UnicodeString("nameSpaces"));
        Array nsItems = (Array) nameSpaces.get(new UnicodeString("org.iso.18013.5.1"));

        assertEquals(1, nsItems.getDataItems().size());
        ByteString retainedItem = (ByteString) nsItems.getDataItems().get(0);

        // Verify that raw bytes are preserved exactly bit-for-bit (Tag 24 preservation)
        assertArrayEquals(item1Bytes, retainedItem.getBytes());

        // Verify SHA-256 hash matches original item bytes
        byte[] expectedDigest = MessageDigest.getInstance("SHA-256").digest(item1Bytes);
        byte[] actualDigest = MessageDigest.getInstance("SHA-256").digest(retainedItem.getBytes());
        assertArrayEquals(expectedDigest, actualDigest);
    }

    @Test
    public void testFilterMdocWithNamespaceQualifiedClaimPath() throws Exception {
        byte[] item1Bytes = encodeItem(0, "given_name", "Alice");
        byte[] item2Bytes = encodeItem(1, "family_name", "Smith");
        String originalMdoc = buildSampleMdoc(item1Bytes, item2Bytes);

        String filteredMdoc = service.filterMdoc(originalMdoc, List.of("org.iso.18013.5.1.family_name"));
        assertNotNull(filteredMdoc);

        byte[] decodedBytes = Base64.getUrlDecoder().decode(filteredMdoc);
        List<DataItem> items = new CborDecoder(new ByteArrayInputStream(decodedBytes)).decode();
        Map doc = (Map) items.get(0);
        Map issuerSigned = (Map) doc.get(new UnicodeString("issuerSigned"));
        Map nameSpaces = (Map) issuerSigned.get(new UnicodeString("nameSpaces"));
        Array nsItems = (Array) nameSpaces.get(new UnicodeString("org.iso.18013.5.1"));

        assertEquals(1, nsItems.getDataItems().size());
        ByteString retainedItem = (ByteString) nsItems.getDataItems().get(0);
        assertArrayEquals(item2Bytes, retainedItem.getBytes());
    }

    @Test
    public void testFilterMdocWhenSelectedClaimsNullReturnsOriginal() {
        String original = "sample-mdoc";
        assertEquals(original, service.filterMdoc(original, null));
    }

    @Test
    public void testFilterMdocWhenEmptyClaimsDisclosesZeroItems() throws Exception {
        byte[] item1Bytes = encodeItem(0, "given_name", "Alice");
        byte[] item2Bytes = encodeItem(1, "family_name", "Smith");
        String originalMdoc = buildSampleMdoc(item1Bytes, item2Bytes);

        String filtered = service.filterMdoc(originalMdoc, Collections.emptyList());
        byte[] decodedBytes = Base64.getUrlDecoder().decode(filtered);
        List<DataItem> items = new CborDecoder(new ByteArrayInputStream(decodedBytes)).decode();
        Map doc = (Map) items.get(0);
        Map issuerSigned = (Map) doc.get(new UnicodeString("issuerSigned"));
        Map nameSpaces = (Map) issuerSigned.get(new UnicodeString("nameSpaces"));
        assertTrue(nameSpaces.getKeys().isEmpty());
    }
}
