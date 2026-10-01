import 'dart:typed_data';

import '../prover.dart';
import 'tlv.dart';

typedef Transceive = Future<Uint8List> Function(Uint8List apdu);

/// What the tap sends the card, from the received challenge.
class TapParams {
  const TapParams({required this.nonce, this.amount, this.currency});

  /// `9F37`, 4 bytes.
  final Uint8List nonce;

  /// Visa only: `9F02` and `5F2A`, which the card signs.
  final Uint8List? amount;
  final Uint8List? currency;
}

/// What the screen shows while the card is read.
class CardIdentity {
  const CardIdentity(this.scheme, this.label, this.last4);

  final CardScheme scheme;

  /// Application Label `50`, e.g. "VISA CREDIT".
  final String label;

  /// `null` until the records holding the PAN are read.
  final String? last4;
}

/// Everything a proof needs from one tap. Kept in memory only.
class CardRead {
  CardRead({
    required this.identity,
    required this.rid,
    required this.caIndex,
    required this.fields,
  });

  final CardIdentity identity;
  final Uint8List rid;

  /// `8F`: the CA key the issuer certificate is signed with.
  final int caIndex;

  /// The native library's `card` object: TLV values in hex.
  final Map<String, Object> fields;
}

/// The card can't be proved; [reason] says why, for the user.
class UnsupportedCard implements Exception {
  UnsupportedCard(this.reason);

  final String reason;

  @override
  String toString() => reason;
}

/// The card left the field, or the link failed, before the read finished.
class CardLost implements Exception {
  @override
  String toString() => 'The card moved away too soon.';
}

/// The card answered a command with an error status word.
class CardRefused implements Exception {
  CardRefused(this.command, this.sw);

  final String command;
  final int sw;

  @override
  String toString() =>
      'The card refused $command (${sw.toRadixString(16).toUpperCase()}).';
}

const _visaRid = 'a000000003';
const _mastercardRid = 'a000000004';

const _otherSchemes = {
  'a000000025': 'American Express',
  'a000000065': 'JCB',
  'a000000152': 'Discover',
  'a000000333': 'UnionPay',
  'a000000524': 'RuPay',
};

/// Key and field lengths in bytes that each circuit is compiled for.
const _issuerCertLength = 248;
const _widths = {
  CardScheme.visaFdda: (iccCert: 176, sdad: 128),
  CardScheme.mastercardDda: (iccCert: 240, sdad: 144),
};

/// Runs one contactless EMV session: PPSE, SELECT, GET PROCESSING OPTIONS with the
/// challenge, READ RECORD, and for Mastercard INTERNAL AUTHENTICATE with the nonce.
class EmvReader {
  EmvReader(this._transceive);

  final Transceive _transceive;

  /// [challenge] is called once the scheme is known, before the card is asked to sign.
  Future<CardRead> read({
    required TapParams Function(CardScheme scheme) challenge,
    void Function(CardIdentity identity)? onIdentified,
  }) async {
    final (:aid, :scheme, :ppseLabel) = await _selectPpse();
    final fci = parseTlv(
      await _send('SELECT', [0x00, 0xA4, 0x04, 0x00, aid.length, ...aid, 0x00]),
    );
    final label =
        _ascii(findTag(fci, 0x50)?.value) ?? ppseLabel ?? scheme.brand;
    onIdentified?.call(CardIdentity(scheme, label, null));

    final params = challenge(scheme);
    final terminal = _Terminal(params);
    final pdol = [
      for (final e in parseDol(findTag(fci, 0x9F38)?.value ?? Uint8List(0)))
        ...terminal.valueFor(e.tag, e.length),
    ];
    final gpo = parseTlv(
      await _send('GET PROCESSING OPTIONS', [
        0x80, 0xA8, 0x00, 0x00, pdol.length + 2, 0x83, pdol.length, //
        ...pdol, 0x00,
      ]),
    );

    // Format 1 (80): AIP then AFL. Format 2 (77): tagged.
    final Uint8List aip;
    final Uint8List afl;
    if (findTag(gpo, 0x80)?.value case final v? when v.length >= 2) {
      aip = v.sublist(0, 2);
      afl = v.sublist(2);
    } else {
      aip = findTag(gpo, 0x82)?.value ?? Uint8List(0);
      afl = findTag(gpo, 0x94)?.value ?? Uint8List(0);
    }

    final nodes = [...gpo];
    final staticData = BytesBuilder();
    for (var i = 0; i + 3 < afl.length; i += 4) {
      final sfi = afl[i] >> 3;
      final (first, last, oda) = (afl[i + 1], afl[i + 2], afl[i + 3]);
      for (var rec = first; rec <= last; rec++) {
        final body = await _send('READ RECORD', [
          0x00, 0xB2, rec, (sfi << 3) | 0x04, 0x00, //
        ]);
        final record = parseTlv(body);
        nodes.addAll(record);
        // EMV Book 3, 10.3: SFI 1 to 10 contribute template 70's value; 11 to 30 the
        // whole record.
        if (rec < first + oda) {
          if (sfi > 10) {
            staticData.add(body);
          } else if (record case [Tlv(tag: 0x70, :final value)]) {
            staticData.add(value);
          } else {
            throw UnsupportedCard("This card's signed records are malformed.");
          }
        }
      }
    }
    final identity = CardIdentity(scheme, label, _last4(nodes));
    onIdentified?.call(identity);

    Uint8List? sdad = findTag(nodes, 0x9F4B)?.value;
    if (scheme == CardScheme.mastercardDda) {
      sdad = await _internalAuthenticate(nodes, params.nonce);
    }
    return _assemble(identity, aid, nodes, aip, staticData.takeBytes(), sdad);
  }

  Future<({Uint8List aid, CardScheme scheme, String? ppseLabel})>
  _selectPpse() async {
    final ppse = '2PAY.SYS.DDF01'.codeUnits;
    final body = await _send('SELECT PPSE', [
      0x00, 0xA4, 0x04, 0x00, ppse.length, ...ppse, 0x00, //
    ]);
    final entries = [
      for (final n in parseTlv(body))
        for (final e in n.walk())
          if (e.tag == 0x61)
            if (findTag(e.children, 0x4F)?.value case final aid?)
              (
                aid: aid,
                label: _ascii(findTag(e.children, 0x50)?.value),
                // Application Priority Indicator: 1 is highest; absent is lowest.
                priority: switch (findTag(e.children, 0x87)?.value) {
                  [final p, ...] when p & 0x0F != 0 => p & 0x0F,
                  _ => 16,
                },
              ),
    ]..sort((a, b) => a.priority.compareTo(b.priority));
    for (final e in entries) {
      final scheme = switch (_rid(e.aid)) {
        _visaRid => CardScheme.visaFdda,
        _mastercardRid => CardScheme.mastercardDda,
        _ => null,
      };
      if (scheme != null) {
        return (aid: e.aid, scheme: scheme, ppseLabel: e.label);
      }
    }
    if (entries.isEmpty) {
      throw UnsupportedCard('This is not a contactless payment card.');
    }
    final name = _otherSchemes[_rid(entries.first.aid)] ?? 'These';
    throw UnsupportedCard(
      '$name cards are not supported yet. zkCard supports Visa and Mastercard.',
    );
  }

  Future<Uint8List?> _internalAuthenticate(
    List<Tlv> nodes,
    Uint8List nonce,
  ) async {
    // Without a card DDOL, the terminal's default DDOL is the Unpredictable Number.
    final ddol = parseDol(
      findTag(nodes, 0x9F49)?.value ?? Uint8List.fromList([0x9F, 0x37, 0x04]),
    );
    if (ddol case [(tag: 0x9F37, length: 4)]) {
      final resp = parseTlv(
        await _send('INTERNAL AUTHENTICATE', [
          0x00, 0x88, 0x00, 0x00, nonce.length, ...nonce, 0x00, //
        ]),
      );
      // Format 2 (77) tags the SDAD; format 1 (80) is the SDAD.
      return findTag(resp, 0x9F4B)?.value ?? findTag(resp, 0x80)?.value;
    }
    throw UnsupportedCard(
      "This card's signed data layout is not supported yet.",
    );
  }

  CardRead _assemble(
    CardIdentity identity,
    Uint8List aid,
    List<Tlv> nodes,
    Uint8List aip,
    Uint8List staticData,
    Uint8List? sdad,
  ) {
    final scheme = identity.scheme;
    final widths = _widths[scheme]!;
    Uint8List need(int tag) =>
        findTag(nodes, tag)?.value ??
        (throw UnsupportedCard(
          'This card does not support offline data authentication.',
        ));
    int exponent(int tag) => switch (need(tag)) {
      [3] => 3,
      _ => throw UnsupportedCard("This card's key exponent is not supported."),
    };
    Uint8List sized(int tag, int length) {
      final v = need(tag);
      if (v.length != length) {
        throw UnsupportedCard("This card's key sizes are not supported yet.");
      }
      return v;
    }

    if (sdad == null) {
      throw UnsupportedCard('The card did not sign the challenge.');
    }
    if (sdad.length != widths.sdad) {
      throw UnsupportedCard("This card's key sizes are not supported yet.");
    }
    final caIndex = switch (need(0x8F)) {
      [final i] => i,
      _ => throw UnsupportedCard("This card's CA key index is malformed."),
    };
    final common = {
      'issuer_cert': hex(sized(0x90, _issuerCertLength)),
      'issuer_exponent': exponent(0x9F32),
      'icc_cert': hex(sized(0x9F46, widths.iccCert)),
      'icc_exponent': exponent(0x9F47),
      'static_data': hex(_staticData(nodes, aip, staticData)),
      'sdad': hex(sdad),
    };
    final Map<String, Object> fields = switch (scheme) {
      CardScheme.visaFdda => {
        'scheme': scheme.id,
        ...common,
        'card_auth_data': hex(sized(0x9F69, 7)),
      },
      CardScheme.mastercardDda => {
        'scheme': scheme.id,
        ...common,
        'issuer_remainder': hex(sized(0x92, 28)),
      },
    };
    return CardRead(
      identity: identity,
      rid: aid.sublist(0, 5),
      caIndex: caIndex,
      fields: fields,
    );
  }

  /// Static data to be authenticated (EMV Book 3, 10.3): the ODA records, then the AIP when
  /// the Static Data Authentication Tag List `9F4A` names it, the only tag Book 3 allows
  /// there. Both circuits take at most 256 bytes.
  static Uint8List _staticData(
    List<Tlv> nodes,
    Uint8List aip,
    Uint8List records,
  ) {
    final tagList = findTag(nodes, 0x9F4A)?.value;
    final withAip = switch (tagList) {
      null => false,
      [0x82] => true,
      _ => throw UnsupportedCard(
        "This card's signed data layout is not supported yet.",
      ),
    };
    final out = Uint8List.fromList([...records, if (withAip) ...aip]);
    if (out.length > 256) {
      throw UnsupportedCard("This card's signed data is too long.");
    }
    return out;
  }

  /// Sends [apdu]; returns the response body. Follows 61XX with GET RESPONSE and retries
  /// 6CXX with the Le the card asks for.
  Future<Uint8List> _send(String command, List<int> apdu) async {
    var resp = await _transmit(Uint8List.fromList(apdu));
    if (resp.length >= 2 && resp[resp.length - 2] == 0x61) {
      resp = await _transmit(
        Uint8List.fromList([0x00, 0xC0, 0x00, 0x00, resp.last]),
      );
    } else if (resp.length >= 2 && resp[resp.length - 2] == 0x6C) {
      resp = await _transmit(
        Uint8List.fromList(apdu)..[apdu.length - 1] = resp.last,
      );
    }
    if (resp.length < 2) throw CardLost();
    final sw = (resp[resp.length - 2] << 8) | resp[resp.length - 1];
    if (sw != 0x9000) throw CardRefused(command, sw);
    return resp.sublist(0, resp.length - 2);
  }

  Future<Uint8List> _transmit(Uint8List apdu) async {
    try {
      return await _transceive(apdu);
    } catch (_) {
      throw CardLost();
    }
  }

  static String _rid(Uint8List aid) => hex(aid.take(5).toList());

  static String? _ascii(Uint8List? bytes) {
    if (bytes == null) return null;
    final s = String.fromCharCodes(bytes.where((b) => b >= 0x20 && b <= 0x7E));
    return s.trim().isEmpty ? null : s.trim();
  }

  /// From the PAN `5A` (BCD, F-padded), else Track 2 `57` (PAN up to separator D).
  static String? _last4(List<Tlv> nodes) {
    final pan = switch ((findTag(nodes, 0x5A), findTag(nodes, 0x57))) {
      (final p?, _) => hex(p.value).replaceAll('f', ''),
      (null, final t?) => hex(t.value).split('d').first,
      _ => null,
    };
    return pan == null || pan.length < 4 ? null : pan.substring(pan.length - 4);
  }
}

/// The values the app offers as a terminal when a PDOL asks for them. From the terminal
/// profile the real taps were captured with, but in the United States and USD.
class _Terminal {
  _Terminal(this.params);

  final TapParams params;

  Uint8List valueFor(int tag, int length) {
    final v = _raw(tag);
    final out = Uint8List(length);
    if (v != null) out.setRange(0, v.length < length ? v.length : length, v);
    return out;
  }

  List<int>? _raw(int tag) {
    final now = DateTime.now();
    return switch (tag) {
      // Terminal Transaction Qualifiers: EMV mode, online PIN, signature, and offline
      // data authentication for online authorisations, which makes Visa sign (fDDA).
      0x9F66 => const [0x27, 0x00, 0x00, 0x00],
      0x9F02 => params.amount,
      0x9F03 => const [0, 0, 0, 0, 0, 0],
      0x9F1A => const [0x08, 0x40], // United States
      0x5F2A => params.currency ?? const [0x08, 0x40], // USD
      0x95 => const [0, 0, 0, 0, 0],
      0x9A => [_bcd(now.year % 100), _bcd(now.month), _bcd(now.day)],
      0x9F21 => [_bcd(now.hour), _bcd(now.minute), _bcd(now.second)],
      0x9C => const [0x00], // purchase
      0x9F37 => params.nonce,
      0x9F35 => const [0x22], // attended, offline with online capability
      0x9F33 => const [0xE0, 0xF8, 0xC8],
      0x9F40 => const [0x60, 0x00, 0xF0, 0xA0, 0x01],
      _ => null,
    };
  }

  static int _bcd(int v) => ((v ~/ 10) << 4) | (v % 10);
}
