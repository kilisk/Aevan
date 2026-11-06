//! Offline tests for the M2 slice: oNCP handshake framing and the ESP packet
//! layer. Nothing in this file opens a socket, touches an interface or needs
//! elevation.

use aevan_nc::esp::{peek_sequence, peek_spi, EspKeys, InboundSa, OutboundSa, NEXT_HEADER_IPV4};
use aevan_nc::ncp::{EspAuthentication, EspEncryption, NcpConfig, KMP_CLIENT_CONFIG, KMP_CONFIG};
use aevan_nc::oncp::{
    client_config_reply, esp_negotiation, handshake_request, hostname_packet,
    parse_esp_negotiation, EspLocalKeys, KmpFrame, OncpError,
};
use aevan_nc::SecretKey;
use serde::Serialize;

const SYNTHETIC_KMP_301: &[u8] = include_bytes!("fixtures/ncp-config-kmp.bin");

fn build_kmp_message(number: u16, payload: &[u8], tail_outbound: bool) -> Vec<u8> {
    let record_len = 20 + payload.len();
    let mut out = Vec::with_capacity(2 + record_len);
    out.extend_from_slice(&(record_len as u16).to_le_bytes());
    out.extend_from_slice(&[0x00; 6]);
    out.extend_from_slice(&number.to_be_bytes());
    if tail_outbound {
        out.extend_from_slice(&[0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00]);
    } else {
        out.extend_from_slice(&[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    }
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

#[test]
fn handshake_request_matches_the_reference_layout() {
    let cookies = vec![
        ("DSID".to_owned(), "abc".to_owned()),
        ("other".to_owned(), "def".to_owned()),
    ];
    let request = handshake_request("vpn.example.com", "aevan/0.1", &cookies).expect("build");
    let expected = concat!(
        "POST /dana/js?prot=1&svc=4 HTTP/1.1\r\n",
        "Connection: close\r\n",
        "Host: vpn.example.com\r\n",
        "User-Agent: aevan/0.1\r\n",
        "Cookie: DSID=abc; other=def\r\n",
        "Content-Length: 256\r\n",
        "\r\n",
    );
    assert_eq!(request, expected.as_bytes());
}

#[test]
fn handshake_request_without_cookies_has_no_cookie_header() {
    let request = handshake_request("host:8443", "ua", &[]).expect("build");
    let text = std::str::from_utf8(&request).expect("utf8");
    assert!(text.contains("Host: host:8443\r\n"));
    assert!(!text.contains("Cookie:"));
    assert!(text.ends_with("Content-Length: 256\r\n\r\n"));
}

#[test]
fn handshake_request_rejects_header_injection() {
    let error = handshake_request("host\r\nX-Evil: 1", "ua", &[]).expect_err("must fail");
    assert!(matches!(error, OncpError::InvalidHeader(_)));
}

#[test]
fn hostname_packet_is_byte_exact() {
    let packet = hostname_packet("aevan-host").expect("build");
    let expected: &[u8] = &[
        0x17, 0x00, // body length, little-endian, excluding the prefix
        0x00, 0x04, 0x00, 0x00, 0x00, // fixed head
        0x0a, 0x00, // hostname length, little-endian
        b'a', b'e', b'v', b'a', b'n', b'-', b'h', b'o', b's', b't', // hostname
        0xbb, 0x01, 0x00, 0x00, 0x00, 0x00, // fixed tail
    ];
    assert_eq!(packet, expected);
    assert_eq!(packet.len(), 2 + 0x17);
}

#[test]
fn client_config_reply_is_byte_exact_for_mtu_1396() {
    let reply = client_config_reply(1396);
    let expected: &[u8] = &[
        0x24, 0x00, // record length, little-endian, excluding the prefix
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // KMP head
        0x01, 0x2f, // KMP 303
        0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, // outbound tag
        0x00, 0x10, // KMP payload length
        0x00, 0x06, // group 6
        0x00, 0x00, 0x00, 0x0a, // group length
        0x00, 0x02, // attribute 2 (MTU)
        0x00, 0x00, 0x00, 0x04, // attribute length
        0x00, 0x00, 0x05, 0x74, // MTU 1396
    ];
    assert_eq!(reply, expected);

    let frame = KmpFrame::parse_outbound(&reply).expect("parse");
    assert_eq!(frame.number, KMP_CLIENT_CONFIG);
    assert_eq!(frame.payload, &expected[22..]);
}

#[test]
fn esp_negotiation_is_byte_exact_for_a_known_key_block() {
    let encryption_key: Vec<u8> = (0u8..16).collect();
    let hmac_key: Vec<u8> = (16u8..36).collect();
    let keys = EspLocalKeys::new(
        0x1a2b_3c4d,
        EspEncryption::Aes128Cbc,
        EspAuthentication::HmacSha1,
        SecretKey::new(encryption_key),
        SecretKey::new(hmac_key),
    )
    .expect("keys");

    let frame = esp_negotiation(&keys);
    let mut expected: Vec<u8> = vec![
        0x6a, 0x00, // record length, little-endian, excluding the prefix
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // KMP head
        0x01, 0x2e, // KMP 302
        0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, // outbound tag
        0x00, 0x56, // KMP payload length (86 bytes on this gateway)
        0x00, 0x07, // group 7
        0x00, 0x00, 0x00, 0x50, // group length
        0x00, 0x01, // attribute 1 (SPI)
        0x00, 0x00, 0x00, 0x04, // attribute length
        0x1a, 0x2b, 0x3c, 0x4d, // SPI
        0x00, 0x02, // attribute 2 (key block)
        0x00, 0x00, 0x00, 0x40, // key block length
    ];
    expected.extend(0u8..36);
    expected.extend(std::iter::repeat_n(0u8, 0x40 - 36));

    assert_eq!(frame, expected);
    assert_eq!(frame.len(), 2 + 20 + 86);

    let parsed = KmpFrame::parse_outbound(&frame).expect("parse");
    assert_eq!(parsed.number, 302);
    assert_eq!(parsed.payload.len(), 86);
}

#[test]
fn generated_esp_key_material_never_appears_in_debug_or_serde() {
    let keys = EspLocalKeys::generate(EspEncryption::Aes128Cbc, EspAuthentication::HmacSha1);
    let debug = format!("{keys:?}");
    assert!(debug.contains("redacted"));
    assert!(!debug.contains("0, 1, 2, 3"));
    assert!(!debug.contains("encryption_key: SecretKey { redacted: false"));

    #[derive(Serialize)]
    struct PublicView<'a> {
        spi: u32,
        #[serde(skip)]
        _keys: &'a EspLocalKeys,
    }
    let json = serde_json::to_string(&PublicView {
        spi: keys.spi(),
        _keys: &keys,
    })
    .expect("json");
    assert_eq!(json, format!("{{\"spi\":{}}}", keys.spi()));

    let block = keys.key_block();
    assert_eq!(block.len(), 0x40);
    let debug_block = format!("{block:?}");
    assert!(debug_block.contains("redacted"));
    assert!(!debug_block.contains("104, 101, 121"));
}

#[test]
fn synthetic_kmp_301_fixture_is_a_config_frame() {
    let frame = KmpFrame::parse(SYNTHETIC_KMP_301).expect("parse");
    assert_eq!(frame.number, KMP_CONFIG);
    assert_eq!(frame.record_length, SYNTHETIC_KMP_301.len() - 2);

    // The existing stage 3 decoder still sees the same message.
    let config = NcpConfig::parse_binary(SYNTHETIC_KMP_301).expect("config");
    assert_eq!(config.mtu, Some(1396));

    // A 301 is not a 302.
    let error = parse_esp_negotiation(
        SYNTHETIC_KMP_301,
        EspEncryption::Aes128Cbc,
        EspAuthentication::HmacSha1,
    )
    .expect_err("must fail");
    assert!(matches!(
        error,
        OncpError::UnexpectedMessage {
            expected: 302,
            actual: 301
        }
    ));
}

#[test]
fn kmp_parser_rejects_truncated_and_overlong_frames() {
    let error = KmpFrame::parse(&SYNTHETIC_KMP_301[..21]).expect_err("must fail");
    assert!(matches!(error, OncpError::Truncated { .. }));

    let mut overlong = SYNTHETIC_KMP_301.to_vec();
    overlong.push(0);
    let error = KmpFrame::parse(&overlong).expect_err("must fail");
    assert!(matches!(error, OncpError::RecordLength { .. }));

    let mut bad_header = SYNTHETIC_KMP_301.to_vec();
    bad_header[2] = 1;
    let error = KmpFrame::parse(&bad_header).expect_err("must fail");
    assert_eq!(error, OncpError::InvalidKmpHeader);
}

fn build_kmp_302(tail_outbound: bool, key_block: &[u8; 0x40]) -> Vec<u8> {
    let mut payload = Vec::new();
    // Group 7, length = attr 1 (6 + 4) + attr 2 (6 + 0x40) = 0x50.
    payload.extend_from_slice(&7u16.to_be_bytes());
    payload.extend_from_slice(&0x50u32.to_be_bytes());
    payload.extend_from_slice(&1u16.to_be_bytes());
    payload.extend_from_slice(&4u32.to_be_bytes());
    payload.extend_from_slice(&0x1a2b_3c4du32.to_be_bytes());
    payload.extend_from_slice(&2u16.to_be_bytes());
    payload.extend_from_slice(&0x40u32.to_be_bytes());
    payload.extend_from_slice(key_block);
    build_kmp_message(302, &payload, tail_outbound)
}

#[test]
fn kmp_302_splits_the_key_block_for_aes128_sha1() {
    let mut block = [0u8; 0x40];
    for (index, byte) in block.iter_mut().enumerate() {
        *byte = index as u8;
    }
    let outbound = build_kmp_302(true, &block);
    let inbound = build_kmp_302(false, &block);

    for parsed in [
        parse_esp_negotiation(
            &outbound,
            EspEncryption::Aes128Cbc,
            EspAuthentication::HmacSha1,
        )
        .expect("outbound tag"),
        parse_esp_negotiation(
            &inbound,
            EspEncryption::Aes128Cbc,
            EspAuthentication::HmacSha1,
        )
        .expect("inbound tag"),
    ] {
        assert_eq!(parsed.outbound_spi, 0x1a2b_3c4d);
        assert_eq!(parsed.encryption_key.expose(), &block[..16]);
        assert_eq!(parsed.hmac_key.expose(), &block[16..36]);
        assert_eq!(parsed.encryption_key.len(), 16);
        assert_eq!(parsed.hmac_key.len(), 20);

        let debug = format!("{parsed:?}");
        assert!(!debug.contains("0, 1, 2, 3"));
        assert!(debug.contains("redacted"));
    }
}

#[test]
fn kmp_302_splits_the_key_block_for_aes256_md5() {
    let mut block = [0u8; 0x40];
    for (index, byte) in block.iter_mut().enumerate() {
        *byte = 0xa0 ^ index as u8;
    }
    let frame = build_kmp_302(false, &block);
    let parsed =
        parse_esp_negotiation(&frame, EspEncryption::Aes256Cbc, EspAuthentication::HmacMd5)
            .expect("parse");
    assert_eq!(parsed.encryption_key.expose(), &block[..32]);
    assert_eq!(parsed.hmac_key.expose(), &block[32..48]);
}

#[test]
fn kmp_302_rejects_non_esp_tlvs() {
    let mut payload = Vec::new();
    payload.extend_from_slice(&1u16.to_be_bytes());
    payload.extend_from_slice(&10u32.to_be_bytes());
    payload.extend_from_slice(&1u16.to_be_bytes());
    payload.extend_from_slice(&4u32.to_be_bytes());
    payload.extend_from_slice(&[10, 0, 0, 1]);
    let frame = build_kmp_message(302, &payload, false);

    let error = parse_esp_negotiation(
        &frame,
        EspEncryption::Aes128Cbc,
        EspAuthentication::HmacSha1,
    )
    .expect_err("must fail");
    assert!(matches!(error, OncpError::NonEspTlv { group: 1, attr: 1 }));
}

#[test]
fn kmp_302_rejects_a_transform_that_disagrees_with_the_config() {
    let mut group_body = Vec::new();
    group_body.extend_from_slice(&1u16.to_be_bytes());
    group_body.extend_from_slice(&1u32.to_be_bytes());
    group_body.push(0x05); // AES-256, while the caller configured AES-128

    let mut payload = Vec::new();
    payload.extend_from_slice(&8u16.to_be_bytes());
    payload.extend_from_slice(&(group_body.len() as u32).to_be_bytes());
    payload.extend_from_slice(&group_body);
    let frame = build_kmp_message(302, &payload, false);

    let error = parse_esp_negotiation(
        &frame,
        EspEncryption::Aes128Cbc,
        EspAuthentication::HmacSha1,
    )
    .expect_err("must fail");
    assert!(matches!(
        error,
        OncpError::TransformMismatch { group: 8, attr: 1 }
    ));
}

#[test]
fn kmp_302_keys_drive_a_full_esp_round_trip() {
    let mut block = [0u8; 0x40];
    for (index, byte) in block.iter_mut().enumerate() {
        *byte = index as u8;
    }
    let frame = build_kmp_302(true, &block);
    let negotiation = parse_esp_negotiation(
        &frame,
        EspEncryption::Aes128Cbc,
        EspAuthentication::HmacSha1,
    )
    .expect("negotiation");

    let keys = EspKeys::from_negotiation(&negotiation).expect("keys");
    let mut outbound = OutboundSa::new(negotiation.outbound_spi, keys.clone(), [0x5a; 16]);
    let mut inbound = InboundSa::new(keys);

    for payload in [b"\x45inner".as_slice(), &[0u8; 64]] {
        let packet = outbound
            .encrypt(payload, NEXT_HEADER_IPV4)
            .expect("encrypt");
        assert_eq!(peek_spi(&packet), Some(0x1a2b_3c4d));
        assert_eq!(peek_sequence(&packet), Some(outbound.next_sequence() - 1));
        let decrypted = inbound.decrypt(&packet).expect("decrypt");
        assert_eq!(decrypted.spi, 0x1a2b_3c4d);
        assert_eq!(decrypted.payload, payload);
        assert_eq!(decrypted.next_header, NEXT_HEADER_IPV4);
    }
}
