import 'package:flutter/material.dart';

import 'package:nfc_manager/nfc_manager_android.dart';

import '../nfc_state.dart';
import '../tap/card_listener.dart';
import '../tap/tap_session.dart';
import '../wallet/store.dart';
import 'tap_screen.dart';
import 'wallet.dart';

class HomePage extends StatefulWidget {
  const HomePage({super.key, required this.nfc, required this.keys});

  /// `null` until the first state arrives.
  final NfcState? nfc;

  /// Completes once the proving and verifying keys are loaded.
  final Future<void> keys;

  @override
  State<HomePage> createState() => _HomePageState();
}

class _HomePageState extends State<HomePage> {
  WalletStore? _store;
  late final _listener = CardListener(_onCard);

  /// The session the tap screen shows; replaced when a card is tapped again.
  final _session = ValueNotifier<TapSession?>(null);
  Route<void>? _tapRoute;

  @override
  void initState() {
    super.initState();
    _listener
      ..attach()
      ..nfcOn = widget.nfc == NfcState.on;
    WalletStore.open().then((store) {
      if (mounted) setState(() => _store = store);
    });
  }

  @override
  void didUpdateWidget(HomePage old) {
    super.didUpdateWidget(old);
    _listener.nfcOn = widget.nfc == NfcState.on;
  }

  @override
  void dispose() {
    _listener.detach();
    _session.dispose();
    super.dispose();
  }

  Future<void> _onCard(IsoDepAndroid card) async {
    final store = _store;
    if (store == null || !mounted) return;
    final session = TapSession(store: store, keys: widget.keys);
    _session.value = session;
    if (_tapRoute == null) {
      final route = PageRouteBuilder<void>(
        pageBuilder: (_, _, _) => TapScreen(session: _session),
        transitionsBuilder: (_, animation, _, child) =>
            FadeTransition(opacity: animation, child: child),
      );
      _tapRoute = route;
      Navigator.of(context).push(route).whenComplete(() => _tapRoute = null);
    }
    await session.run(card.transceive);
    if (session.value.phase == TapPhase.done) {
      await Future<void>.delayed(const Duration(seconds: 2));
      final route = _tapRoute;
      if (mounted && route != null && route.isCurrent) {
        Navigator.of(context).pop();
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final store = _store;
    return Scaffold(
      appBar: AppBar(title: const Text('zkCard')),
      // The wallet sits low, within reach of a thumb.
      body: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 24),
        child: store == null
            ? null
            : ListenableBuilder(
                listenable: store,
                builder: (context, _) => Column(
                  children: [
                    const Spacer(flex: 2),
                    Wallet(cards: store.cards),
                    if (store.cards.isEmpty) ...[
                      const SizedBox(height: 16),
                      Text(
                        'Your zkCard wallet is empty',
                        style: theme.textTheme.titleLarge,
                        textAlign: TextAlign.center,
                      ),
                    ],
                    const Spacer(),
                  ],
                ),
              ),
      ),
      bottomNavigationBar: switch (widget.nfc) {
        NfcState.on => const _Banner(
          'Hold a contactless card on the back of your phone.',
          icon: Icons.contactless,
          color: Color(0xFF00C853),
        ),
        NfcState.off => const _Banner(
          'NFC is off. Turn it on in Settings.',
          icon: Icons.nfc,
          color: Color(0xFFFF1744),
        ),
        NfcState.unsupported => const _Banner(
          'This device has no NFC.',
          icon: Icons.nfc,
          color: Color(0xFFFF1744),
        ),
        null => null,
      },
    );
  }
}

class _Banner extends StatelessWidget {
  const _Banner(this.message, {required this.icon, required this.color});

  final String message;
  final IconData icon;
  final Color color;

  @override
  Widget build(BuildContext context) {
    const foreground = Colors.white;
    // The system gesture area below stays the page's colour; the strip only fits the text.
    return SafeArea(
      top: false,
      child: Material(
        color: color,
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 3),
          child: Row(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              Icon(icon, size: 14, color: foreground),
              const SizedBox(width: 6),
              Text(
                message,
                style: Theme.of(context).textTheme.bodySmall
                    ?.copyWith(color: foreground),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
