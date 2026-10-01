import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:zkcard/emv/reader.dart';
import 'package:zkcard/emv/tlv.dart';
import 'package:zkcard/prover.dart';

/// A card that answers the reader's APDUs from a synthetic tap in `circuits/fixtures/`.
/// It doesn't sign: the reader only extracts, and the native tests prove.
class FakeCard {
  FakeCard(String fixture, {this.aid, this.iccCertLength, this.dropAfter}) {
    final doc = jsonDecode(
      File('../circuits/fixtures/$fixture.json').readAsStringSync(),
    ) as Map<String, Object?>;
    for (final e in (doc['elements']! as List).cast<Map<String, Object?>>()) {
      tags[e['tag']! as String] = fromHex(e['value']! as String);
    }
    selectedAid = fromHex(doc['selectedAid']! as String);
    final oda = (doc['exchanges']! as List)
        .cast<Map<String, Object?>>()
        .firstOrNull;
    odaCommand = oda == null ? null : fromHex(oda['command']! as String);
    odaRecord = oda == null ? null : fromHex(oda['response']! as String);
  }

  final tags = <String, Uint8List>{};
  late final Uint8List selectedAid;

  /// The ODA record's READ RECORD command and full response, whose template 70 value is
  /// hashed; `null` on a card without one. The chain's records are served from SFI 1 (Visa)
  /// or SFI 3 (Mastercard), so they never collide with it.
  late final Uint8List? odaCommand;
  late final Uint8List? odaRecord;

  /// Overrides, to exercise rejections.
  final Uint8List? aid;
  final int? iccCertLength;

  /// Throws, as a card leaving the field does, after this many APDUs.
  final int? dropAfter;

  final commands = <Uint8List>[];

  bool get visa => tags.containsKey('9F69');
  Uint8List get _aid => aid ?? selectedAid;

  Future<Uint8List> transceive(Uint8List apdu) async {
    commands.add(apdu);
    if (dropAfter != null && commands.length > dropAfter!) {
      throw StateError('Tag was lost.');
    }
    final ok = [0x90, 0x00];
    Uint8List t(String tag) => tags[tag]!;
    final Uint8List body = switch ((apdu[0], apdu[1], apdu[2], apdu[3])) {
      (0x00, 0xA4, _, _) when apdu[5] == 0x32 => tlv(0x6F, [
        ...tlv(0x84, '2PAY.SYS.DDF01'.codeUnits),
        ...tlv(0xA5, [
          ...tlv(0xBF0C, [
            ...tlv(0x61, [
              ...tlv(0x4F, _aid),
              ...tlv(0x50, 'TEST CARD'.codeUnits),
              ...tlv(0x87, [1]),
            ]),
          ]),
        ]),
      ]),
      (0x00, 0xA4, _, _) => tlv(0x6F, [
        ...tlv(0x84, _aid),
        ...tlv(0xA5, [
          ...tlv(0x50, 'TEST CARD'.codeUnits),
          if (visa) ...tlv(0x9F38, t('9F38')),
        ]),
      ]),
      (0x80, 0xA8, _, _) => tlv(0x77, [
        ...tlv(0x82, t('82')),
        ...tlv(0x94, [
          if (odaCommand case final c?) ...[c[3] & 0xF8, c[2], c[2], 1],
          ...visa ? [0x08, 1, 1, 0] : [0x18, 1, 2, 0],
        ]),
        if (visa) ...[
          ...tlv(0x9F36, t('9F36')),
          ...tlv(0x9F4B, t('9F4B')),
          ...tlv(0x9F69, t('9F69')),
        ],
      ]),
      (0x00, 0xB2, final rec, final p2)
          when odaCommand != null &&
              rec == odaCommand![2] &&
              p2 == odaCommand![3] =>
        odaRecord!.sublist(0, odaRecord!.length - 2),
      (0x00, 0xB2, final rec, _) => tlv(0x70, [
        if (visa || rec == 1) ...[
          ...tlv(0x8F, t('8F')),
          ...tlv(0x90, t('90')),
          ...tlv(0x9F32, t('9F32')),
          if (!visa) ...tlv(0x92, t('92')),
        ],
        if (visa || rec == 2) ...[
          ...tlv(
            0x9F46,
            iccCertLength == null ? t('9F46') : Uint8List(iccCertLength!),
          ),
          ...tlv(0x9F47, t('9F47')),
          if (visa) ...tlv(0x5A, t('5A')),
        ],
      ]),
      (0x00, 0x88, _, _) => tlv(0x77, tlv(0x9F4B, t('9F4B'))),
      _ => throw StateError('unexpected APDU ${hex(apdu)}'),
    };
    return Uint8List.fromList([...body, ...ok]);
  }
}

Uint8List tlv(int tag, List<int> value) {
  final t = tag > 0xFF ? [tag >> 8, tag & 0xFF] : [tag];
  final n = value.length;
  final len = n < 0x80
      ? [n]
      : n < 0x100
      ? [0x81, n]
      : [0x82, n >> 8, n & 0xFF];
  return Uint8List.fromList([...t, ...len, ...value]);
}

final nonce = Uint8List.fromList([0xDE, 0xAD, 0xBE, 0xEF]);
final amount = fromHex('000000000100');
final currency = fromHex('0356');

Future<CardRead> read(FakeCard card, {List<CardIdentity>? seen}) =>
    EmvReader(card.transceive).read(
      challenge: (scheme) => TapParams(
        nonce: nonce,
        amount: scheme == CardScheme.visaFdda ? amount : null,
        currency: scheme == CardScheme.visaFdda ? currency : null,
      ),
      onIdentified: seen?.add,
    );

void main() {
  test('Visa fDDA: fields, identity, and the challenge in the PDOL', () async {
    final card = FakeCard('visa_fdda');
    final seen = <CardIdentity>[];
    final r = await read(card, seen: seen);

    expect(r.identity.scheme, CardScheme.visaFdda);
    expect(r.identity.label, 'TEST CARD');
    expect(
      r.identity.last4,
      hex(card.tags['5A']!).replaceAll('f', '').substring(12),
    );
    expect(seen.map((i) => i.last4), [null, r.identity.last4]);
    expect(hex(r.rid), 'a000000003');
    expect(r.caIndex, card.tags['8F']![0]);
    expect(r.fields, {
      'scheme': 'visa_fdda',
      'issuer_cert': hex(card.tags['90']!),
      'issuer_exponent': 3,
      'icc_cert': hex(card.tags['9F46']!),
      'icc_exponent': 3,
      'static_data': '',
      'sdad': hex(card.tags['9F4B']!),
      'card_auth_data': hex(card.tags['9F69']!),
    });

    // The PDOL's values, in order: the challenge's nonce, amount and currency are where
    // the card's PDOL puts them.
    final gpo = card.commands.firstWhere((c) => c[0] == 0x80 && c[1] == 0xA8);
    final data = gpo.sublist(7, gpo.length - 1);
    var at = 0;
    for (final e in parseDol(card.tags['9F38']!)) {
      final v = data.sublist(at, at += e.length);
      if (e.tag == 0x9F37) expect(v, nonce);
      if (e.tag == 0x9F02) expect(v, amount);
      if (e.tag == 0x5F2A) expect(v, currency);
    }
    expect(at, data.length);
  });

  test(
    'Mastercard DDA: static data, and the nonce to INTERNAL AUTHENTICATE',
    () async {
      final card = FakeCard('mastercard_dda');
      final r = await read(card);
      final record = card.odaRecord!;
      // The ODA record's template 70 value (70 81 len), then the AIP, as 9F4A = 82.
      final staticData = [
        ...record.sublist(3, record.length - 2),
        ...card.tags['82']!,
      ];

      expect(r.identity.scheme, CardScheme.mastercardDda);
      expect(hex(r.rid), 'a000000004');
      expect(r.fields, {
        'scheme': 'mastercard_dda',
        'issuer_cert': hex(card.tags['90']!),
        'issuer_exponent': 3,
        'icc_cert': hex(card.tags['9F46']!),
        'icc_exponent': 3,
        'sdad': hex(card.tags['9F4B']!),
        'issuer_remainder': hex(card.tags['92']!),
        'static_data': hex(staticData),
      });
      final auth = card.commands.firstWhere((c) => c[1] == 0x88);
      expect(auth.sublist(5, 9), nonce);
    },
  );

  test(
    'Visa fDDA with an ODA record: its value and the AIP are static data',
    () async {
      final card = FakeCard('visa_fdda_oda');
      final r = await read(card);
      final record = card.odaRecord!;
      // Template 70 with a short length: tag, length, then the value.
      final value = record.sublist(2, record.length - 2);
      expect(value.length, record[1]);
      expect(r.fields['static_data'], hex([...value, ...card.tags['82']!]));
      expect(r.fields['sdad'], hex(card.tags['9F4B']!));
      expect(
        card.commands.any((c) => c[1] == 0xB2 && c[2] == 3 && c[3] == 0x1C),
        isTrue,
        reason: 'reads the ODA record, SFI 3 record 3',
      );
    },
  );

  test('another scheme is named', () async {
    final card = FakeCard('visa_fdda', aid: fromHex('a0000005241010'));
    await expectLater(
      read(card),
      throwsA(
        isA<UnsupportedCard>().having(
          (e) => e.reason,
          'reason',
          contains('RuPay'),
        ),
      ),
    );
  });

  test('other key sizes are unsupported', () async {
    final card = FakeCard('visa_fdda', iccCertLength: 144);
    await expectLater(
      read(card),
      throwsA(
        isA<UnsupportedCard>().having(
          (e) => e.reason,
          'reason',
          contains('key sizes'),
        ),
      ),
    );
  });

  test('a card leaving the field mid-read is lost', () async {
    await expectLater(
      read(FakeCard('mastercard_dda', dropAfter: 4)),
      throwsA(isA<CardLost>()),
    );
  });
}
