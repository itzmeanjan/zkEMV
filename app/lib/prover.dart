import 'dart:isolate';

import 'package:flutter/services.dart';

import 'native/zkemv.dart';

enum CardScheme {
  visaFdda('visa_fdda', 'Visa', 'Visa fDDA'),
  mastercardDda('mastercard_dda', 'Mastercard', 'Mastercard DDA');

  const CardScheme(this.id, this.brand, this.label);

  /// The circuit package and the native library's scheme name.
  final String id;
  final String brand;
  final String label;

  static CardScheme fromId(String id) => values.firstWhere(
    (s) => s.id == id,
    orElse: () => throw FormatException('unknown scheme $id'),
  );
}

/// The origin every challenge is issued for and received from, so a card's nullifier in
/// the verifier scope is stable across taps.
const origin = 'zkcard.emv';

abstract final class Prover {
  static const _assets = 'assets/generated';

  /// Loads both schemes' keys, the CA table and the BIN table into the native library.
  static Future<void> load() async {
    final blobs = <(String, Uint8List)>[
      for (final s in CardScheme.values) ...[
        ('load_proving_key', await _asset('keys/${s.id}.pkp')),
        ('load_verifying_key', await _asset('keys/${s.id}.pkv')),
      ],
      ('load_ca_table', await _asset('certificate-authority-public-keys.json')),
      ('load_bin_table', await _asset('bin-table.json')),
    ];
    await Isolate.run(() {
      for (final (method, blob) in blobs) {
        Zkemv.call(method, blob: blob);
      }
    });
  }

  static Future<Uint8List> _asset(String path) async =>
      (await rootBundle.load('$_assets/$path')).buffer.asUint8List();
}
