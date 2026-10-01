import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';

import '../emv/reader.dart';
import '../tap/tap_session.dart';

/// Covers the home screen while a card is read and proved. Follows [session], which the
/// home page replaces when the card is tapped again after a failure.
class TapScreen extends StatelessWidget {
  const TapScreen({super.key, required this.session});

  final ValueListenable<TapSession?> session;

  @override
  Widget build(BuildContext context) => ValueListenableBuilder(
    valueListenable: session,
    builder: (context, s, _) => s == null
        ? const _TapView(TapStatus(TapPhase.reading))
        : ValueListenableBuilder(
            valueListenable: s,
            builder: (context, status, _) => _TapView(status),
          ),
  );
}

class _TapView extends StatelessWidget {
  const _TapView(this.status);

  final TapStatus status;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final colors = theme.colorScheme;
    final name = _name(status.identity);
    final (color, title, hint) = switch (status.phase) {
      TapPhase.reading => (
        colors.primary,
        'Adding card',
        'Hold the card still on the back of your phone.',
      ),
      TapPhase.proving => (
        colors.primary,
        'Proving possession',
        'You can remove the card now.',
      ),
      TapPhase.verifying => (
        colors.primary,
        'Verifying the proof',
        'Almost done.',
      ),
      TapPhase.done => (
        const Color(0xFF00C853),
        'Proved possession of card in ${humanDuration(status.prove!)}',
        status.newCard
            ? 'Added to your wallet.'
            : 'Already in your wallet. The new proof is saved with it.',
      ),
      TapPhase.failed => (
        colors.error,
        'Could not add card',
        '${status.error}\nTap the card again to retry.',
      ),
    };

    // The waves fill the screen from its centre; the text sits below the centre.
    return Scaffold(
      body: Stack(
        children: [
          Positioned.fill(
            child: Waves(
              color: color,
              child: Icon(Icons.contactless, size: 72, color: color),
            ),
          ),
          Positioned.fill(
            child: SafeArea(
              child: Padding(
                padding: const EdgeInsets.all(24),
                child: Column(
                  children: [
                    const Spacer(),
                    const SizedBox(height: 180),
                    AnimatedSwitcher(
                      duration: const Duration(milliseconds: 300),
                      child: Text(
                        title,
                        key: ValueKey(title),
                        style: theme.textTheme.headlineSmall,
                        textAlign: TextAlign.center,
                      ),
                    ),
                    if (name != null) ...[
                      const SizedBox(height: 8),
                      Text(
                        name,
                        style: theme.textTheme.titleMedium?.copyWith(
                          fontFeatures: const [FontFeature.tabularFigures()],
                        ),
                      ),
                    ],
                    const SizedBox(height: 16),
                    Text(
                      hint,
                      style: theme.textTheme.bodyMedium?.copyWith(
                        color: colors.onSurfaceVariant,
                      ),
                      textAlign: TextAlign.center,
                    ),
                    const Spacer(),
                    if (status.phase == TapPhase.failed)
                      FilledButton(
                        onPressed: () => Navigator.of(context).pop(),
                        child: const Text('Close'),
                      ),
                  ],
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }

  static String? _name(CardIdentity? id) => switch (id) {
    null => null,
    CardIdentity(:final label, last4: null) => label,
    CardIdentity(:final label, :final last4?) => '$label •••• $last4',
  };
}

/// "0.7 seconds", "12 seconds", "1 min 5 s".
String humanDuration(Duration d) {
  final s = d.inMicroseconds / Duration.microsecondsPerSecond;
  if (s < 10) return '${s.toStringAsFixed(1)} seconds';
  if (s < 60) return '${s.round()} seconds';
  final rest = d.inSeconds % 60;
  return rest == 0 ? '${d.inMinutes} min' : '${d.inMinutes} min $rest s';
}

/// Rings that ripple out from the centre across the whole area, around [child].
class Waves extends StatefulWidget {
  const Waves({super.key, required this.color, required this.child});

  final Color color;
  final Widget child;

  @override
  State<Waves> createState() => _WavesState();
}

class _WavesState extends State<Waves> with SingleTickerProviderStateMixin {
  late final _controller = AnimationController(
    vsync: this,
    duration: const Duration(milliseconds: 3000),
  )..repeat();

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => CustomPaint(
    painter: _WavesPainter(_controller, widget.color),
    child: Center(child: widget.child),
  );
}

class _WavesPainter extends CustomPainter {
  _WavesPainter(this.progress, this.color) : super(repaint: progress);

  static const _rings = 4;
  static const _inner = 64.0;

  final Animation<double> progress;
  final Color color;

  @override
  void paint(Canvas canvas, Size size) {
    final center = size.center(Offset.zero);
    final outer = size.longestSide * 0.6;
    canvas.drawCircle(
      center,
      _inner,
      Paint()..color = color.withValues(alpha: 0.14),
    );
    for (var i = 0; i < _rings; i++) {
      final t = (progress.value + i / _rings) % 1;
      canvas.drawCircle(
        center,
        _inner + (outer - _inner) * t,
        Paint()
          ..color = color.withValues(alpha: (1 - t) * 0.45)
          ..style = PaintingStyle.stroke
          ..strokeWidth = 3,
      );
    }
  }

  @override
  bool shouldRepaint(_WavesPainter old) => old.color != color;
}
