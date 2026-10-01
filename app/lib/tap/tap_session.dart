import 'dart:isolate';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import '../emv/reader.dart';
import '../emv/tlv.dart';
import '../native/zkemv.dart';
import '../prover.dart';
import '../wallet/model.dart';
import '../wallet/store.dart';

enum TapPhase { reading, proving, verifying, done, failed }

class TapStatus {
  const TapStatus(
    this.phase, {
    this.identity,
    this.error,
    this.prove,
    this.newCard = false,
  });

  final TapPhase phase;
  final CardIdentity? identity;

  /// For [TapPhase.failed]: why, for the user.
  final String? error;

  /// For [TapPhase.done].
  final Duration? prove;
  final bool newCard;

  TapStatus copyWith(TapPhase phase, {CardIdentity? identity}) =>
      TapStatus(phase, identity: identity ?? this.identity);
}

/// One tap: reads the card with a fresh challenge, proves and verifies on the device,
/// then stores the proof. The card's data stays in memory and is dropped when this ends.
class TapSession extends ValueNotifier<TapStatus> {
  TapSession({required this.store, required this.keys})
    : super(const TapStatus(TapPhase.reading));

  final WalletStore store;

  /// Completes once the proving and verifying keys are loaded.
  final Future<void> keys;

  Future<void> run(Transceive transceive) async {
    int? issued;
    try {
      String? challenge;
      final read = await EmvReader(transceive).read(
        challenge: (scheme) {
          final c = _issue(scheme);
          issued = c.id;
          challenge = c.challenge;
          return c.params;
        },
        onIdentified: (id) => value = TapStatus(TapPhase.reading, identity: id),
      );
      // The card can go: a short pulse says so.
      await const MethodChannel('zkcard/haptics').invokeMethod('pulse', 60);
      value = value.copyWith(TapPhase.proving, identity: read.identity);

      final ca = {
        'challenge': challenge!,
        'origin': origin,
        'rid': hex(read.rid),
        'index': read.caIndex,
      };
      try {
        Zkemv.callJson('check_ca', input: ca);
      } on ZkemvException {
        throw UnsupportedCard("zkCard doesn't have this card's CA key.");
      }
      await keys;
      final (proof, prove) = await Isolate.run(
        _proveTask({...ca, 'card': read.fields}),
      );

      value = value.copyWith(TapPhase.verifying);
      final verifyRequest = {...ca, 'id': issued!}..remove('challenge');
      final (nullifier, verify) = await Isolate.run(
        _verifyTask(verifyRequest, proof),
      );
      issued = null;

      final cardId =
          nullifier ?? (throw ZkemvException('the proof carries no nullifier'));
      final newCard = !store.cards.any((c) => c.id == cardId);
      final now = DateTime.now();
      await store.add(
        WalletCard(
          id: cardId,
          scheme: read.identity.scheme,
          last4: read.identity.last4 ?? '····',
          addedAt: now,
        ),
        ProofRecord(
          id: '${now.microsecondsSinceEpoch}',
          cardId: cardId,
          createdAt: now,
          challenge: challenge!,
          nonce: hex(_nonceOf(challenge!)),
          year: now.year,
          month: now.month,
          rid: hex(read.rid),
          caIndex: read.caIndex,
          prove: prove,
          verify: verify,
          proofBytes: proof.length,
        ),
        proof,
      );
      value = TapStatus(
        TapPhase.done,
        identity: read.identity,
        prove: prove,
        newCard: newCard,
      );
    } catch (e) {
      value = TapStatus(
        TapPhase.failed,
        identity: value.identity,
        error: _describe(e),
      );
    } finally {
      if (issued != null) Zkemv.call('forget', input: {'id': issued});
    }
  }

  /// The app is its own verifier for now: it issues the challenge, and the prover side
  /// reads it back as a received one.
  static ({int id, String challenge, TapParams params}) _issue(
    CardScheme scheme,
  ) {
    final now = DateTime.now();
    final visa = scheme == CardScheme.visaFdda;
    final issued = Zkemv.callJson(
      'issue',
      input: {
        'scheme': scheme.id,
        'origin': origin,
        'scope': 'verifier',
        'year': now.year,
        'month': now.month,
        // No money moves: the amount is zero.
        if (visa) 'amount': '000000000000',
        if (visa) 'currency': '0840', // USD
      },
    );
    final challenge = issued['challenge']! as String;
    final r = Zkemv.callJson(
      'receive',
      input: {'challenge': challenge, 'origin': origin},
    );
    Uint8List? bytes(Object? h) => h == null ? null : fromHex(h as String);
    return (
      id: issued['id']! as int,
      challenge: challenge,
      params: TapParams(
        nonce: bytes(r['nonce'])!,
        amount: bytes(r['amount']),
        currency: bytes(r['currency']),
      ),
    );
  }

  // Isolate entry points are built here, not in `run`, so they capture only their
  // arguments: a closure in an instance method may capture the unsendable notifier.
  static (Uint8List, Duration) Function() _proveTask(
    Map<String, Object> request,
  ) => () {
    final sw = Stopwatch()..start();
    final proof = Zkemv.call('prove', input: request);
    return (proof, sw.elapsed);
  };

  static (String?, Duration) Function() _verifyTask(
    Map<String, Object> request,
    Uint8List proof,
  ) => () {
    final sw = Stopwatch()..start();
    final out = Zkemv.callJson('verify', input: request, blob: proof);
    return (out['nullifier'] as String?, sw.elapsed);
  };

  /// `Challenge::to_bytes`: scheme tag, then the 4-byte nonce.
  static Uint8List _nonceOf(String challenge) =>
      fromHex(challenge).sublist(1, 5);

  static String _describe(Object e) => switch (e) {
    UnsupportedCard(:final reason) => reason,
    CardLost() =>
      'The card moved away too soon. Hold it still until the phone vibrates.',
    CardRefused() => '$e',
    ZkemvException(:final message) => 'Proving failed: $message',
    _ => 'Something went wrong: $e',
  };
}
