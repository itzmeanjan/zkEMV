import 'dart:async';

import 'package:flutter/material.dart';

import 'nfc_state.dart';
import 'prover.dart';
import 'ui/home_page.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  // Loaded from the start, so the first tap doesn't wait. A failure surfaces when a tap
  // awaits the keys.
  final keys = Prover.load()..ignore();
  runApp(ZkCardApp(keys: keys));
}

class ZkCardApp extends StatefulWidget {
  const ZkCardApp({super.key, required this.keys});

  final Future<void> keys;

  @override
  State<ZkCardApp> createState() => _ZkCardAppState();
}

class _ZkCardAppState extends State<ZkCardApp> {
  NfcState? _nfc;
  late final StreamSubscription<NfcState> _sub;

  @override
  void initState() {
    super.initState();
    _sub = nfcStates().listen((s) => setState(() => _nfc = s));
  }

  @override
  void dispose() {
    _sub.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => MaterialApp(
    title: 'zkCard',
    theme: _theme(_nfc, Brightness.light),
    darkTheme: _theme(_nfc, Brightness.dark),
    themeAnimationDuration: const Duration(milliseconds: 500),
    home: HomePage(nfc: _nfc, keys: widget.keys),
  );
}

/// Light green while NFC is on, light red while it is off or missing.
ThemeData _theme(NfcState? nfc, Brightness brightness) {
  final light = brightness == Brightness.light;
  final (seed, background) = switch (nfc) {
    null => (Colors.indigo, null),
    NfcState.on => (
      Colors.green,
      light ? const Color(0xFFD4F5DA) : const Color(0xFF17331D),
    ),
    NfcState.off || NfcState.unsupported => (
      Colors.red,
      light ? const Color(0xFFFFD6D6) : const Color(0xFF3D1A1A),
    ),
  };
  return ThemeData(
    colorScheme: ColorScheme.fromSeed(seedColor: seed, brightness: brightness),
    useMaterial3: true,
    scaffoldBackgroundColor: background,
    appBarTheme: AppBarTheme(backgroundColor: background),
  );
}
