package `in`.itzmeanjan.zkcard

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.nfc.NfcAdapter
import android.os.Build
import android.os.VibrationEffect
import android.os.Vibrator
import android.os.VibratorManager
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.EventChannel
import io.flutter.plugin.common.MethodChannel

class MainActivity : FlutterActivity() {
    private var nfcState: NfcStateStream? = null

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        val stream = NfcStateStream(applicationContext)
        EventChannel(flutterEngine.dartExecutor.binaryMessenger, "zkcard/nfc_state").setStreamHandler(stream)
        nfcState = stream
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, "zkcard/haptics").setMethodCallHandler { call, result ->
            if (call.method == "pulse") {
                pulse(call.arguments as? Int ?: 60)
                result.success(null)
            } else {
                result.notImplemented()
            }
        }
    }

    // The vibrator itself, not View haptics: those are silent when touch feedback is off.
    private fun pulse(millis: Int) {
        val vibrator = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            getSystemService(VibratorManager::class.java).defaultVibrator
        } else {
            getSystemService(Vibrator::class.java)
        }
        vibrator?.vibrate(VibrationEffect.createOneShot(millis.toLong(), VibrationEffect.DEFAULT_AMPLITUDE))
    }

    // In case a change was missed while the app was in the background.
    override fun onResume() {
        super.onResume()
        nfcState?.emitCurrent()
    }
}

/** Streams "on", "off" or "unsupported": the current state on listen, then every change. */
private class NfcStateStream(private val context: Context) : EventChannel.StreamHandler {
    private var events: EventChannel.EventSink? = null
    private var receiver: BroadcastReceiver? = null

    fun emitCurrent() {
        val adapter = NfcAdapter.getDefaultAdapter(context)
        events?.success(
            when {
                adapter == null -> "unsupported"
                adapter.isEnabled -> "on"
                else -> "off"
            },
        )
    }

    override fun onListen(arguments: Any?, sink: EventChannel.EventSink) {
        events = sink
        emitCurrent()
        if (NfcAdapter.getDefaultAdapter(context) == null) return
        val r = object : BroadcastReceiver() {
            override fun onReceive(c: Context, intent: Intent) {
                when (intent.getIntExtra(NfcAdapter.EXTRA_ADAPTER_STATE, NfcAdapter.STATE_OFF)) {
                    NfcAdapter.STATE_ON -> events?.success("on")
                    NfcAdapter.STATE_OFF -> events?.success("off")
                }
            }
        }
        val filter = IntentFilter(NfcAdapter.ACTION_ADAPTER_STATE_CHANGED)
        // Exported: the NFC service, a separate app, sends this broadcast, not the system server.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            context.registerReceiver(r, filter, Context.RECEIVER_EXPORTED)
        } else {
            context.registerReceiver(r, filter)
        }
        receiver = r
    }

    override fun onCancel(arguments: Any?) {
        receiver?.let(context::unregisterReceiver)
        receiver = null
        events = null
    }
}
