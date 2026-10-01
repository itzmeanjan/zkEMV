import 'package:flutter/widgets.dart';
import 'package:nfc_manager/nfc_manager.dart';
import 'package:nfc_manager/nfc_manager_android.dart';

/// Keeps Android's reader mode on while the app is in the foreground and NFC is on, and
/// hands each ISO-DEP card to [onCard]. Reader mode reports a card once per entry into the
/// field, so a card left on the phone isn't read again; cards arriving while [onCard]
/// runs are ignored.
class CardListener with WidgetsBindingObserver {
  CardListener(this.onCard);

  final Future<void> Function(IsoDepAndroid card) onCard;

  var _foreground = true;
  var _nfcOn = false;
  var _listening = false;
  var _busy = false;
  Future<void> _pending = Future.value();

  void attach() => WidgetsBinding.instance.addObserver(this);

  void detach() {
    WidgetsBinding.instance.removeObserver(this);
    _sync(false);
  }

  set nfcOn(bool on) {
    _nfcOn = on;
    _sync(_foreground && _nfcOn);
  }

  // `inactive` covers the notification shade, where NFC is often toggled: keep listening.
  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    _foreground =
        state == AppLifecycleState.resumed ||
        state == AppLifecycleState.inactive;
    _sync(_foreground && _nfcOn);
  }

  /// Serialized, so a quick off-on can't leave the session in the wrong state.
  void _sync(bool listen) => _pending = _pending.then((_) async {
    if (listen == _listening) return;
    try {
      if (listen) {
        await NfcManager.instance.startSession(
          pollingOptions: {NfcPollingOption.iso14443},
          onDiscovered: _discovered,
        );
      } else {
        await NfcManager.instance.stopSession();
      }
      _listening = listen;
    } catch (_) {
      // NFC went away in between; the next state change retries.
    }
  });

  Future<void> _discovered(NfcTag tag) async {
    final card = IsoDepAndroid.from(tag);
    if (_busy || card == null) return;
    _busy = true;
    try {
      try {
        await card.setTimeout(5000);
      } catch (_) {
        // Optional; some devices refuse.
      }
      await onCard(card);
    } finally {
      _busy = false;
    }
  }
}
