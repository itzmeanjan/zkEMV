import 'package:flutter/services.dart';

enum NfcState { on, off, unsupported }

/// The NFC adapter's state now, then on every change (`MainActivity`'s `NfcStateStream`).
Stream<NfcState> nfcStates() =>
    const EventChannel('zkcard/nfc_state')
        .receiveBroadcastStream()
        .map((s) => NfcState.values.byName(s as String));
