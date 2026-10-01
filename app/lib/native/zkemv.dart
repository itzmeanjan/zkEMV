import 'dart:convert';
import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

final class _Bytes extends Struct {
  external Pointer<Uint8> ptr;

  @Size()
  external int len;
}

final class _Result extends Struct {
  @Uint32()
  external int status;

  external _Bytes data;
}

typedef _CallNative = _Result Function(
  Pointer<Uint8>,
  Size,
  Pointer<Uint8>,
  Size,
  Pointer<Uint8>,
  Size,
);
typedef _Call = _Result Function(
  Pointer<Uint8>,
  int,
  Pointer<Uint8>,
  int,
  Pointer<Uint8>,
  int,
);

class ZkemvException implements Exception {
  ZkemvException(this.message);

  final String message;

  @override
  String toString() => message;
}

/// Bindings to `libzkemv.so` (`app/native`). Calls block, so run `prove`, `verify`,
/// `self_test` and key loading off the UI isolate. The library's state (keys, CA table,
/// issued challenges) is process-wide, shared by all isolates.
abstract final class Zkemv {
  static final _lib = DynamicLibrary.open('libzkemv.so');
  static final _call = _lib.lookupFunction<_CallNative, _Call>('zkemv_call');
  static final _free = _lib
      .lookupFunction<Void Function(_Bytes), void Function(_Bytes)>(
        'zkemv_free',
      );

  /// Runs `method` on the JSON `input` and the `blob`; returns the raw output.
  static Uint8List call(String method, {Object? input, Uint8List? blob}) {
    final args = [
      utf8.encode(method),
      input == null ? Uint8List(0) : utf8.encode(jsonEncode(input)),
      blob ?? Uint8List(0),
    ];
    final ptrs = [for (final a in args) _copyIn(a)];
    try {
      final result = _call(
        ptrs[0],
        args[0].length,
        ptrs[1],
        args[1].length,
        ptrs[2],
        args[2].length,
      );
      final data = result.data.len == 0
          ? Uint8List(0)
          : Uint8List.fromList(result.data.ptr.asTypedList(result.data.len));
      _free(result.data);
      if (result.status != 0) throw ZkemvException(utf8.decode(data));
      return data;
    } finally {
      ptrs.forEach(calloc.free);
    }
  }

  /// [call] for methods whose output is JSON.
  static Map<String, Object?> callJson(
    String method, {
    Object? input,
    Uint8List? blob,
  }) =>
      jsonDecode(utf8.decode(call(method, input: input, blob: blob)))
          as Map<String, Object?>;

  static Pointer<Uint8> _copyIn(Uint8List bytes) {
    final ptr = calloc<Uint8>(bytes.isEmpty ? 1 : bytes.length);
    ptr.asTypedList(bytes.length).setAll(0, bytes);
    return ptr;
  }
}
