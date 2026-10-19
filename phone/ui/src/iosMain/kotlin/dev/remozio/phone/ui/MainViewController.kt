package dev.remozio.phone.ui

import androidx.compose.ui.window.ComposeUIViewController
import platform.UIKit.UIViewController

/** Entry point for the Swift shell, exported as `MainViewControllerKt.MainViewController(services:)`. */
fun MainViewController(services: PhoneServices): UIViewController = ComposeUIViewController { RemozioApp(services) }
