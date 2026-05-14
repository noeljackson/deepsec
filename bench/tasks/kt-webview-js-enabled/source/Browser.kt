package com.example.browser

import android.webkit.WebView

fun configureWebViewVulnerable(view: WebView) {
    view.settings.javaScriptEnabled = true
}

fun configureWebViewSafe(view: WebView) {
    view.settings.javaScriptEnabled = false
}

fun renderTitle(label: String) = "browser: $label"
