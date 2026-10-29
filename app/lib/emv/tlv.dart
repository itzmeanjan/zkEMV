import 'dart:typed_data';

/// A BER-TLV node, as EMV encodes everything a card returns.
class Tlv {
  Tlv(this.tag, this.value, this.children);

  /// Multi-byte tags keep all their bytes, e.g. 0x9F46.
  final int tag;
  final Uint8List value;
  final List<Tlv> children;

  Iterable<Tlv> walk() sync* {
    yield this;
    for (final c in children) {
      yield* c.walk();
    }
  }
}

/// Parses BER-TLV. Skips 0x00/0xFF padding between objects and truncates an overlong
/// value, as real cards produce both.
List<Tlv> parseTlv(Uint8List data) {
  final out = <Tlv>[];
  var i = 0;
  while (i < data.length) {
    if (data[i] == 0x00 || data[i] == 0xFF) {
      i++;
      continue;
    }
    final tagStart = i;
    final first = data[i++];
    if (first & 0x1F == 0x1F) {
      while (i < data.length && data[i++] & 0x80 != 0) {}
    }
    if (i >= data.length) break;
    var tag = 0;
    for (var k = tagStart; k < i; k++) {
      tag = (tag << 8) | data[k];
    }

    var len = data[i++];
    if (len == 0x80) break; // indefinite length: not used in EMV
    if (len > 0x80) {
      final n = len & 0x7F;
      len = 0;
      for (var k = 0; k < n && i < data.length; k++) {
        len = (len << 8) | data[i++];
      }
    }
    if (i + len > data.length) len = data.length - i;
    final value = Uint8List.fromList(data.sublist(i, i + len));
    i += len;
    out.add(Tlv(tag, value, first & 0x20 != 0 ? parseTlv(value) : const []));
  }
  return out;
}

/// The first node with [tag] anywhere in [nodes], depth first.
Tlv? findTag(Iterable<Tlv> nodes, int tag) {
  for (final n in nodes) {
    for (final m in n.walk()) {
      if (m.tag == tag) return m;
    }
  }
  return null;
}

/// A Data Object List (PDOL, DDOL): tag and length pairs, no values.
List<({int tag, int length})> parseDol(Uint8List dol) {
  final out = <({int tag, int length})>[];
  var i = 0;
  while (i < dol.length) {
    final tagStart = i;
    final first = dol[i++];
    if (first & 0x1F == 0x1F) {
      while (i < dol.length && dol[i++] & 0x80 != 0) {}
    }
    if (i >= dol.length) break;
    var tag = 0;
    for (var k = tagStart; k < i; k++) {
      tag = (tag << 8) | dol[k];
    }
    out.add((tag: tag, length: dol[i++]));
  }
  return out;
}

String hex(List<int> bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

Uint8List fromHex(String s) => Uint8List.fromList([
  for (var i = 0; i + 1 < s.length; i += 2)
    int.parse(s.substring(i, i + 2), radix: 16),
]);
