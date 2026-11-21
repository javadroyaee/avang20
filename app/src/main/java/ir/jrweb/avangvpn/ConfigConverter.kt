package ir.jrweb.avangvpn

import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject
import java.net.URI
import java.net.URLDecoder

object ConfigConverter {

    fun buildSingBoxConfig(config: VpnConfig): String {
        val outbound = when (config.protocol) {
            "VLESS" -> parseVlessOutbound(config.rawUri)
            "VMESS" -> parseVmessOutbound(config.rawUri)
            "TROJAN" -> parseTrojanOutbound(config.rawUri)
            "SS" -> parseShadowsocksOutbound(config.rawUri)
            "WIREGUARD" -> parseWireGuardOutbound(config.rawUri)
            else -> parseVlessOutbound(config.rawUri)
        }

        val root = JSONObject().apply {
            put("log", JSONObject().put("level", "warn"))
            put("dns", JSONObject().apply {
                put("servers", JSONArray().apply {
                    put(JSONObject().put("tag", "remote").put("address", "1.1.1.1").put("detour", "proxy"))
                    put(JSONObject().put("tag", "direct").put("address", "223.5.5.5").put("detour", "direct"))
                })
            })
            put("inbounds", JSONArray().apply {
                put(JSONObject().apply {
                    put("type", "tun")
                    put("tag", "tun-in")
                    put("inet4_address", "172.19.0.1/30")
                    put("auto_route", true)
                    put("strict_route", false)
                    put("sniff", true)
                })
            })
            put("outbounds", JSONArray().apply {
                put(outbound)
                put(JSONObject().put("type", "direct").put("tag", "direct"))
                put(JSONObject().put("type", "dns").put("tag", "dns-out"))
            })
            put("route", JSONObject().apply {
                put("auto_detect_interface", true)
                put("rules", JSONArray().apply {
                    put(JSONObject().put("protocol", "dns").put("outbound", "dns-out"))
                    put(JSONObject().put("ip_is_private", true).put("outbound", "direct"))
                })
            })
        }
        return root.toString(2)
    }

    private fun parseQuery(query: String?): Map<String, String> {
        val map = mutableMapOf<String, String>()
        if (query.isNullOrEmpty()) return map
        for (pair in query.split("&")) {
            val idx = pair.indexOf("=")
            if (idx > 0) {
                val k = URLDecoder.decode(pair.substring(0, idx), "UTF-8")
                val v = URLDecoder.decode(pair.substring(idx + 1), "UTF-8")
                map[k] = v
            }
        }
        return map
    }

    private fun parseVlessOutbound(uriStr: String): JSONObject {
        val uri = URI(uriStr)
        val params = parseQuery(uri.rawQuery)
        val out = JSONObject().apply {
            put("type", "vless")
            put("tag", "proxy")
            put("server", uri.host)
            put("server_port", if (uri.port > 0) uri.port else 443)
            put("uuid", uri.userInfo ?: "")
        }
        val flow = params["flow"]
        if (!flow.isNullOrEmpty()) out.put("flow", flow)

        applyTransportAndTls(out, params, uri.host ?: "")
        return out
    }

    private fun parseTrojanOutbound(uriStr: String): JSONObject {
        val uri = URI(uriStr)
        val params = parseQuery(uri.rawQuery)
        val out = JSONObject().apply {
            put("type", "trojan")
            put("tag", "proxy")
            put("server", uri.host)
            put("server_port", if (uri.port > 0) uri.port else 443)
            put("password", uri.userInfo ?: "")
        }
        applyTransportAndTls(out, params, uri.host ?: "")
        return out
    }

    private fun parseVmessOutbound(uriStr: String): JSONObject {
        val b64 = uriStr.removePrefix("vmess://")
        val json = JSONObject(String(Base64.decode(b64, Base64.DEFAULT)))
        val out = JSONObject().apply {
            put("type", "vmess")
            put("tag", "proxy")
            put("server", json.optString("add"))
            put("server_port", json.optInt("port", 443))
            put("uuid", json.optString("id"))
            put("alter_id", json.optInt("aid", 0))
            put("security", json.optString("scy", "auto"))
        }
        val net = json.optString("net", "tcp")
        if (net == "ws") {
            out.put("transport", JSONObject().apply {
                put("type", "ws")
                put("path", json.optString("path", "/"))
                val host = json.optString("host")
                if (host.isNotEmpty()) {
                    put("headers", JSONObject().put("Host", host))
                }
            })
        } else if (net == "grpc") {
            out.put("transport", JSONObject().apply {
                put("type", "grpc")
                put("service_name", json.optString("path", ""))
            })
        }
        if (json.optString("tls") == "tls") {
            out.put("tls", JSONObject().apply {
                put("enabled", true)
                put("server_name", json.optString("sni", json.optString("host", json.optString("add"))))
                put("insecure", true)
            })
        }
        return out
    }

    private fun parseShadowsocksOutbound(uriStr: String): JSONObject {
        val uri = URI(uriStr)
        val userInfo = String(Base64.decode(uri.userInfo ?: "", Base64.DEFAULT))
        val method = userInfo.substringBefore(":", "aes-256-gcm")
        val pass = userInfo.substringAfter(":", "")
        return JSONObject().apply {
            put("type", "shadowsocks")
            put("tag", "proxy")
            put("server", uri.host)
            put("server_port", if (uri.port > 0) uri.port else 8388)
            put("method", method)
            put("password", pass)
        }
    }

    private fun parseWireGuardOutbound(raw: String): JSONObject {
        if (raw.contains("[Interface]")) {
            var privKey = ""
            var localAddr = "10.0.0.2/32"
            var pubKey = ""
            var endpoint = ""
            for (line in raw.lines()) {
                val t = line.trim()
                when {
                    t.startsWith("PrivateKey", true) -> privKey = t.substringAfter("=").trim()
                    t.startsWith("Address", true) -> localAddr = t.substringAfter("=").trim().substringBefore(",")
                    t.startsWith("PublicKey", true) -> pubKey = t.substringAfter("=").trim()
                    t.startsWith("Endpoint", true) -> endpoint = t.substringAfter("=").trim()
                }
            }
            val host = endpoint.substringBefore(":")
            val port = endpoint.substringAfter(":", "51820").toIntOrNull() ?: 51820
            return JSONObject().apply {
                put("type", "wireguard")
                put("tag", "proxy")
                put("server", host)
                put("server_port", port)
                put("local_address", JSONArray().put(localAddr))
                put("private_key", privKey)
                put("peer_public_key", pubKey)
            }
        } else {
            val normalized = raw.replace("wg://", "wireguard://")
            val uri = URI(normalized)
            val params = parseQuery(uri.rawQuery)
            return JSONObject().apply {
                put("type", "wireguard")
                put("tag", "proxy")
                put("server", uri.host)
                put("server_port", if (uri.port > 0) uri.port else 51820)
                put("local_address", JSONArray().put(params["address"] ?: "10.0.0.2/32"))
                put("private_key", uri.userInfo ?: "")
                put("peer_public_key", params["publickey"] ?: "")
            }
        }
    }

    private fun applyTransportAndTls(out: JSONObject, params: Map<String, String>, defaultHost: String) {
        val type = params["type"] ?: "tcp"
        when (type) {
            "ws" -> {
                out.put("transport", JSONObject().apply {
                    put("type", "ws")
                    put("path", params["path"] ?: "/")
                    val host = params["host"]
                    if (!host.isNullOrEmpty()) {
                        put("headers", JSONObject().put("Host", host))
                    }
                })
            }
            "grpc" -> {
                out.put("transport", JSONObject().apply {
                    put("type", "grpc")
                    put("service_name", params["serviceName"] ?: "")
                })
            }
        }

        val security = params["security"] ?: ""
        if (security == "tls" || security == "reality") {
            val tlsObj = JSONObject().apply {
                put("enabled", true)
                put("server_name", params["sni"] ?: params["host"] ?: defaultHost)
                put("insecure", true)
                val fp = params["fp"]
                if (!fp.isNullOrEmpty()) {
                    put("utls", JSONObject().put("enabled", true).put("fingerprint", fp))
                }
            }
            if (security == "reality") {
                tlsObj.put("reality", JSONObject().apply {
                    put("enabled", true)
                    put("public_key", params["pbk"] ?: "")
                    put("short_id", params["sid"] ?: "")
                })
            }
            out.put("tls", tlsObj)
        }
    }
}