import 'dart:math';
import 'dart:ui';

import 'package:flutter/material.dart';

import '../prover.dart';
import '../wallet/model.dart';

/// ISO/IEC 7810 ID-1: 85.60 × 53.98 mm.
const cardAspectRatio = 85.60 / 53.98;

const _leather = Color(0xFF4E342E);
const _pocketTop = Color(0xFF795548);
const _pocketBottom = Color(0xFF5D4037);
const _stitch = Color(0xFFD7CCC8);
const _clasp = Color(0xFF3E2723);

/// An empty wallet: a dashed placeholder card rises out of the pocket and sinks back.
class EmptyWallet extends StatefulWidget {
  const EmptyWallet({super.key});

  @override
  State<EmptyWallet> createState() => _EmptyWalletState();
}

class _EmptyWalletState extends State<EmptyWallet>
    with SingleTickerProviderStateMixin {
  late final _controller = AnimationController(
    vsync: this,
    duration: const Duration(milliseconds: 2200),
  )..repeat(reverse: true);

  late final _rise = CurvedAnimation(
    parent: _controller,
    curve: Curves.easeInOutCubic,
  );

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => LayoutBuilder(
    builder: (context, constraints) {
      final width = min(constraints.maxWidth, 360.0);
      final cardWidth = width * 0.82;
      final cardHeight = cardWidth / cardAspectRatio;
      final pocketHeight = cardHeight * 0.72;
      final bodyHeight = pocketHeight + 28;
      final walletHeight = pocketHeight + cardHeight * 0.62;
      final pocketTop = walletHeight - pocketHeight;
      final lowered = pocketTop + 12;
      final raised = pocketTop - cardHeight * 0.55;

      return SizedBox(
        width: width,
        height: walletHeight,
        child: AnimatedBuilder(
          animation: _rise,
          builder: (context, _) => Stack(
            children: [
              Positioned(
                left: 0,
                right: 0,
                bottom: 0,
                height: bodyHeight,
                child: const DecoratedBox(
                  decoration: BoxDecoration(
                    color: _leather,
                    borderRadius: BorderRadius.all(Radius.circular(22)),
                  ),
                ),
              ),
              Positioned(
                left: (width - cardWidth) / 2,
                top: lerpDouble(lowered, raised, _rise.value),
                width: cardWidth,
                height: cardHeight,
                child: Opacity(
                  opacity: lerpDouble(0.4, 1, _rise.value)!,
                  child: const _PlaceholderCard(),
                ),
              ),
              Positioned(
                left: 0,
                right: 0,
                bottom: 0,
                height: pocketHeight,
                child: const CustomPaint(painter: _PocketPainter()),
              ),
            ],
          ),
        ),
      );
    },
  );
}

/// The wallet: [EmptyWallet] without cards, else the cards peeking out of the pocket,
/// oldest at the back. Each card slides in when it first appears.
class Wallet extends StatelessWidget {
  const Wallet({super.key, required this.cards});

  final List<WalletCard> cards;

  @override
  Widget build(BuildContext context) {
    if (cards.isEmpty) return const EmptyWallet();
    return LayoutBuilder(
      builder: (context, constraints) {
        final width = min(constraints.maxWidth, 360.0);
        final cardWidth = width * 0.82;
        final cardHeight = cardWidth / cardAspectRatio;
        final pocketHeight = cardHeight * 0.72;
        final n = cards.length;
        // Each card behind shows a strip with its brand and last four digits.
        final step = n == 1 ? 0.0 : min(44.0, 220.0 / (n - 1));
        final frontShown = cardHeight * 0.5;
        final height = pocketHeight + frontShown + step * (n - 1) + 8;
        final pocketTop = height - pocketHeight;

        return SizedBox(
          width: width,
          height: height,
          child: Stack(
            clipBehavior: Clip.none,
            children: [
              Positioned(
                left: 0,
                right: 0,
                bottom: 0,
                height: pocketHeight + 28,
                child: const DecoratedBox(
                  decoration: BoxDecoration(
                    color: _leather,
                    borderRadius: BorderRadius.all(Radius.circular(22)),
                  ),
                ),
              ),
              for (final (i, card) in cards.indexed)
                Positioned(
                  key: ValueKey(card.id),
                  left: (width - cardWidth) / 2,
                  top: pocketTop - frontShown - step * (n - 1 - i),
                  width: cardWidth,
                  height: cardHeight,
                  child: _SlideIn(child: CardFace(card: card)),
                ),
              Positioned(
                left: 0,
                right: 0,
                bottom: 0,
                height: pocketHeight,
                child: const CustomPaint(painter: _PocketPainter()),
              ),
            ],
          ),
        );
      },
    );
  }
}

/// Drops its child in from above, once, when first built.
class _SlideIn extends StatefulWidget {
  const _SlideIn({required this.child});

  final Widget child;

  @override
  State<_SlideIn> createState() => _SlideInState();
}

class _SlideInState extends State<_SlideIn>
    with SingleTickerProviderStateMixin {
  late final _controller = AnimationController(
    vsync: this,
    duration: const Duration(milliseconds: 900),
  )..forward();

  late final _drop = CurvedAnimation(
    parent: _controller,
    curve: Curves.easeOutBack,
  );

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => AnimatedBuilder(
    animation: _drop,
    builder: (context, child) => Transform.translate(
      offset: Offset(0, -240 * (1 - _drop.value)),
      child: Opacity(opacity: _controller.value, child: child),
    ),
    child: widget.child,
  );
}

/// A card in the wallet: its brand and last four digits along the top edge, the part that
/// shows when cards overlap. Its colour derives from the card's id.
class CardFace extends StatelessWidget {
  const CardFace({super.key, required this.card});

  final WalletCard card;

  static const _visa = [
    [Color(0xFF1A237E), Color(0xFF3F51B5)],
    [Color(0xFF0D47A1), Color(0xFF1E88E5)],
    [Color(0xFF004D40), Color(0xFF26A69A)],
    [Color(0xFF311B92), Color(0xFF7E57C2)],
  ];
  static const _mastercard = [
    [Color(0xFF212121), Color(0xFF546E7A)],
    [Color(0xFFBF360C), Color(0xFFFF7043)],
    [Color(0xFF880E4F), Color(0xFFEC407A)],
    [Color(0xFF3E2723), Color(0xFF8D6E63)],
  ];

  @override
  Widget build(BuildContext context) {
    final palette = switch (card.scheme) {
      CardScheme.visaFdda => _visa,
      CardScheme.mastercardDda => _mastercard,
    };
    final colors =
        palette[int.parse(card.id.substring(0, 8), radix: 16) % palette.length];
    const text = TextStyle(color: Colors.white, fontWeight: FontWeight.w600);
    return DecoratedBox(
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(14),
        gradient: LinearGradient(
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
          colors: colors,
        ),
        boxShadow: const [
          BoxShadow(
            color: Colors.black26,
            blurRadius: 6,
            offset: Offset(0, -1),
          ),
        ],
      ),
      child: Padding(
        padding: const EdgeInsets.fromLTRB(16, 12, 16, 16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Text(card.scheme.brand, style: text.copyWith(fontSize: 17)),
                const Spacer(),
                Text(
                  '•••• ${card.last4}',
                  style: text.copyWith(
                    fontSize: 15,
                    fontFeatures: const [FontFeature.tabularFigures()],
                  ),
                ),
              ],
            ),
            const SizedBox(height: 14),
            Row(
              children: [
                Container(
                  width: 38,
                  height: 28,
                  decoration: BoxDecoration(
                    borderRadius: BorderRadius.circular(5),
                    gradient: const LinearGradient(
                      colors: [Color(0xFFFFE082), Color(0xFFFFB300)],
                    ),
                  ),
                ),
                const SizedBox(width: 12),
                const Icon(Icons.contactless, color: Colors.white70),
              ],
            ),
          ],
        ),
      ),
    );
  }
}

class _PlaceholderCard extends StatelessWidget {
  const _PlaceholderCard();

  @override
  Widget build(BuildContext context) {
    final color = Theme.of(context).colorScheme.primary;
    return CustomPaint(
      painter: _DashedCardPainter(color),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Align(
          alignment: Alignment.topRight,
          child: Icon(Icons.contactless_outlined, color: color, size: 28),
        ),
      ),
    );
  }
}

class _DashedCardPainter extends CustomPainter {
  const _DashedCardPainter(this.color);

  final Color color;

  @override
  void paint(Canvas canvas, Size size) {
    final rect = RRect.fromRectAndRadius(
      Offset.zero & size,
      const Radius.circular(14),
    );
    canvas.drawRRect(rect, Paint()..color = color.withValues(alpha: 0.12));
    _dash(
      canvas,
      Path()..addRRect(rect.deflate(1)),
      Paint()
        ..color = color
        ..style = PaintingStyle.stroke
        ..strokeWidth = 2,
      dash: 10,
      gap: 6,
    );
  }

  @override
  bool shouldRepaint(_DashedCardPainter old) => old.color != color;
}

class _PocketPainter extends CustomPainter {
  const _PocketPainter();

  @override
  void paint(Canvas canvas, Size size) {
    final rect = RRect.fromRectAndCorners(
      Offset.zero & size,
      topLeft: const Radius.circular(10),
      topRight: const Radius.circular(10),
      bottomLeft: const Radius.circular(22),
      bottomRight: const Radius.circular(22),
    );
    canvas.drawShadow(Path()..addRRect(rect), Colors.black, 6, false);
    canvas.drawRRect(
      rect,
      Paint()
        ..shader = const LinearGradient(
          begin: Alignment.topCenter,
          end: Alignment.bottomCenter,
          colors: [_pocketTop, _pocketBottom],
        ).createShader(Offset.zero & size),
    );
    _dash(
      canvas,
      Path()..addRRect(rect.deflate(9)),
      Paint()
        ..color = _stitch.withValues(alpha: 0.7)
        ..style = PaintingStyle.stroke
        ..strokeWidth = 1.6,
      dash: 7,
      gap: 5,
    );

    // The clasp: a strap over the right edge, with a snap button.
    final strap = RRect.fromLTRBR(
      size.width * 0.78,
      size.height * 0.34,
      size.width + 6,
      size.height * 0.66,
      const Radius.circular(12),
    );
    canvas.drawRRect(strap, Paint()..color = _clasp);
    canvas.drawCircle(
      Offset(size.width * 0.84, size.height * 0.5),
      size.height * 0.07,
      Paint()..color = _stitch,
    );
  }

  @override
  bool shouldRepaint(_PocketPainter old) => false;
}

void _dash(
  Canvas canvas,
  Path path,
  Paint paint, {
  required double dash,
  required double gap,
}) {
  for (final metric in path.computeMetrics()) {
    for (var d = 0.0; d < metric.length; d += dash + gap) {
      canvas.drawPath(metric.extractPath(d, d + dash), paint);
    }
  }
}
