import '../prover.dart';

/// A card in the wallet. Holds no card data but the PAN's last four digits, for display.
class WalletCard {
  WalletCard({
    required this.id,
    required this.scheme,
    required this.last4,
    required this.addedAt,
  });

  factory WalletCard.fromJson(Map<String, Object?> j) => WalletCard(
    id: j['id']! as String,
    scheme: CardScheme.fromId(j['scheme']! as String),
    last4: j['last4']! as String,
    addedAt: DateTime.parse(j['addedAt']! as String),
  );

  /// The card's nullifier in the `zkcard.emv` verifier scope: the same for every proof of
  /// one card, so proofs group by it without keeping the PAN.
  final String id;
  final CardScheme scheme;

  /// Unsigned on Visa: a label, not a proved value.
  final String last4;
  final DateTime addedAt;

  Map<String, Object?> toJson() => {
    'id': id,
    'scheme': scheme.id,
    'last4': last4,
    'addedAt': addedAt.toUtc().toIso8601String(),
  };
}

/// One proof of a card, and the public inputs it was proved for.
class ProofRecord {
  ProofRecord({
    required this.id,
    required this.cardId,
    required this.createdAt,
    required this.challenge,
    required this.nonce,
    required this.year,
    required this.month,
    required this.rid,
    required this.caIndex,
    required this.prove,
    required this.verify,
    required this.proofBytes,
  });

  factory ProofRecord.fromJson(Map<String, Object?> j) => ProofRecord(
    id: j['id']! as String,
    cardId: j['cardId']! as String,
    createdAt: DateTime.parse(j['createdAt']! as String),
    challenge: j['challenge']! as String,
    nonce: j['nonce']! as String,
    year: j['year']! as int,
    month: j['month']! as int,
    rid: j['rid']! as String,
    caIndex: j['caIndex']! as int,
    prove: Duration(microseconds: j['proveUs']! as int),
    verify: switch (j['verifyUs']) {
      final int us => Duration(microseconds: us),
      _ => null,
    },
    proofBytes: j['proofBytes']! as int,
  );

  final String id;
  final String cardId;
  final DateTime createdAt;

  /// The challenge's wire bytes, hex: scheme, nonce, month, Visa's transaction, scope.
  final String challenge;

  /// `9F37`, hex.
  final String nonce;
  final int year;
  final int month;

  /// The CA key the proof is under: RID (hex) and index `8F`.
  final String rid;
  final int caIndex;

  final Duration prove;

  /// `null` if the proof was not verified on the device.
  final Duration? verify;
  final int proofBytes;

  Map<String, Object?> toJson() => {
    'id': id,
    'cardId': cardId,
    'createdAt': createdAt.toUtc().toIso8601String(),
    'challenge': challenge,
    'nonce': nonce,
    'year': year,
    'month': month,
    'rid': rid,
    'caIndex': caIndex,
    'proveUs': prove.inMicroseconds,
    'verifyUs': verify?.inMicroseconds,
    'proofBytes': proofBytes,
  };
}
