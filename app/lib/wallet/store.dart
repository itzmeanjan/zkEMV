import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:path_provider/path_provider.dart';

import 'model.dart';

/// The wallet, in app-private storage: `wallet/index.json` holds the cards and proof
/// records, `wallet/proofs/<id>.proof` each proof's bytes. Every write goes to a temporary
/// file first, then is renamed over the old one.
class WalletStore extends ChangeNotifier {
  WalletStore._(this._dir, this._cards, this._proofs);

  static const _version = 1;

  final Directory _dir;
  final List<WalletCard> _cards;
  final List<ProofRecord> _proofs;

  static Future<WalletStore> open() async {
    final dir = Directory(
      '${(await getApplicationSupportDirectory()).path}/wallet',
    );
    await Directory('${dir.path}/proofs').create(recursive: true);
    final index = File('${dir.path}/index.json');
    if (!await index.exists()) return WalletStore._(dir, [], []);
    final j = jsonDecode(await index.readAsString()) as Map<String, Object?>;
    if (j['version'] != _version) {
      throw FormatException('wallet index version ${j['version']}');
    }
    List<Map<String, Object?>> list(String key) =>
        (j[key]! as List).cast<Map<String, Object?>>();
    return WalletStore._(
      dir,
      list('cards').map(WalletCard.fromJson).toList(),
      list('proofs').map(ProofRecord.fromJson).toList(),
    );
  }

  /// In the order they were added.
  List<WalletCard> get cards => List.unmodifiable(_cards);

  /// Newest first.
  List<ProofRecord> proofsOf(String cardId) =>
      _proofs.where((p) => p.cardId == cardId).toList()
        ..sort((a, b) => b.createdAt.compareTo(a.createdAt));

  int proofCount(String cardId) =>
      _proofs.where((p) => p.cardId == cardId).length;

  Future<Uint8List> proofBytes(ProofRecord p) => _proofFile(p.id).readAsBytes();

  /// Adds `proof`, and `card` if the wallet doesn't hold it yet.
  Future<void> add(WalletCard card, ProofRecord proof, Uint8List bytes) async {
    await _write(_proofFile(proof.id), bytes);
    final cards = [..._cards, if (!_cards.any((c) => c.id == card.id)) card];
    final proofs = [..._proofs, proof];
    await _writeIndex(cards, proofs);
    _cards
      ..clear()
      ..addAll(cards);
    _proofs
      ..clear()
      ..addAll(proofs);
    notifyListeners();
  }

  File _proofFile(String id) => File('${_dir.path}/proofs/$id.proof');

  Future<void> _writeIndex(List<WalletCard> cards, List<ProofRecord> proofs) =>
      _write(
        File('${_dir.path}/index.json'),
        utf8.encode(
          jsonEncode({
            'version': _version,
            'cards': [for (final c in cards) c.toJson()],
            'proofs': [for (final p in proofs) p.toJson()],
          }),
        ),
      );

  static Future<void> _write(File file, List<int> bytes) async {
    final tmp = File('${file.path}.tmp');
    await tmp.writeAsBytes(bytes, flush: true);
    await tmp.rename(file.path);
  }
}
