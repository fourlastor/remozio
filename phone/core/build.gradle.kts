plugins {
    alias(libs.plugins.kotlin.jvm)
    `java-test-fixtures`
}

kotlin { jvmToolchain(21) }

dependencies {
    implementation(project(":protocol-kotlin"))
    api(project(":phone-pairing"))
    api(project(":phone-enrollment"))
    testFixturesImplementation(project(":protocol-kotlin"))
    implementation(libs.ktor.websockets)
    implementation(libs.kotlinx.coroutines.core)
    testImplementation(libs.bouncycastle.bcprov)
    testImplementation(libs.okhttp.mockwebserver3)
    testImplementation(libs.okhttp.tls)
    testImplementation(kotlin("test-junit"))
    testImplementation(libs.kotlinx.coroutines.test)
    testImplementation(libs.junit)
    testImplementation(libs.kotlinx.serialization.json)
}

// The enrollment model moved to a multiplatform module for iOS. This module keeps its access to the internal members,
// and the Android app still has none.
tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile>().configureEach {
    friendPaths.from(libraries.filter { it.name.startsWith("phone-enrollment") })
}

val capture = rootProject.layout.projectDirectory.file("android/app/src/debug/res/raw/sample_command.cbor")
tasks.withType<Test>().configureEach {
    useJUnit()
    // CI keeps no test reports; print the failing assertion and its stack in the log.
    testLogging {
        events(org.gradle.api.tasks.testing.logging.TestLogEvent.FAILED)
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
    }
    val historyVectors = rootProject.layout.projectDirectory.file("protocol/vectors/audit-history-status-v1.json")
    inputs.file(historyVectors)
    systemProperty("remozio.test.auditHistoryVectors", historyVectors.asFile.absolutePath)
    val commandVectors4 = rootProject.layout.projectDirectory.file("protocol/vectors/command-capture-v4.json")
    inputs.file(commandVectors4)
    systemProperty("remozio.test.commandVectors4", commandVectors4.asFile.absolutePath)
    val commandVectors3 = rootProject.layout.projectDirectory.file("protocol/vectors/command-capture-v3.json")
    inputs.file(commandVectors3)
    systemProperty("remozio.test.commandVectors3", commandVectors3.asFile.absolutePath)
    inputs.file(capture)
    systemProperty("remozio.test.commandCapture", capture.asFile.absolutePath)
}

tasks.test { exclude("**/ApprovalFlowTest.class", "**/AuditFlowTest.class", "**/HPKEInteropTest.class", "**/TLSInteropTest.class", "**/PairingSetupInteropTest.class", "**/LinuxPairToolLoopbackTest.class") }

// Linux only: pairs the JVM phone client with the software-key remozio-linux-pair experiment over loopback.
// scripts/check-linux-pairing-peer.sh builds the binary; REMOZIO_LINUX_PAIR_TOOL overrides its path.
tasks.register<Test>("linuxPairToolTest") {
    description = "Pairs the JVM phone client with the Linux software-key pairing tool over loopback TLS."
    group = "verification"
    dependsOn(tasks.testClasses)
    testClassesDirs = sourceSets.test.get().output.classesDirs
    classpath = sourceSets.test.get().runtimeClasspath
    filter { includeTestsMatching("dev.remozio.phone.crypto.LinuxPairToolLoopbackTest") }
    val tool = providers.environmentVariable("REMOZIO_LINUX_PAIR_TOOL").map { file(it) }.orElse(
        rootProject.layout.projectDirectory.file(".build/linux-swift/pairing-peer/build/debug/remozio-linux-pair").asFile)
    inputs.file(tool)
    systemProperty("remozio.test.linuxPairTool", tool.get().absolutePath)
}

tasks.register<Test>("approvalFlowTest") {
    description = "Runs synthetic Swift and Kotlin approval and audit peers on a Mac."
    group = "verification"
    dependsOn(tasks.testClasses)
    testClassesDirs = sourceSets.test.get().output.classesDirs
    classpath = sourceSets.test.get().runtimeClasspath
    filter {
        includeTestsMatching("dev.remozio.phone.requests.ApprovalFlowTest")
        includeTestsMatching("dev.remozio.phone.audit.AuditFlowTest")
        includeTestsMatching("dev.remozio.phone.crypto.HPKEInteropTest")
        includeTestsMatching("dev.remozio.phone.crypto.TLSInteropTest")
        includeTestsMatching("dev.remozio.phone.crypto.PairingSetupInteropTest")
    }
    val peer = rootProject.layout.projectDirectory.file(
        ".build/approval-flow/ApprovalFlowPeer")
    inputs.file(peer)
    systemProperty("remozio.test.swiftPeer", peer.asFile.absolutePath)
    val tlsPeer = rootProject.layout.projectDirectory.file(".build/approval-flow/TLSPeer")
    inputs.file(tlsPeer)
    systemProperty("remozio.test.tlsPeer", tlsPeer.asFile.absolutePath)
    val hpkePeer = rootProject.layout.projectDirectory.file(".build/approval-flow/HPKEPeer")
    inputs.file(hpkePeer)
    systemProperty("remozio.test.hpkePeer", hpkePeer.asFile.absolutePath)
    val auditPeer = rootProject.layout.projectDirectory.file(".build/approval-flow/AuditFlowPeer")
    inputs.file(auditPeer)
    systemProperty("remozio.test.auditPeer", auditPeer.asFile.absolutePath)
    val nativeTransportEvidence = layout.buildDirectory.dir("reports/native-transport-evidence")
    outputs.dir(nativeTransportEvidence)
    systemProperty("remozio.test.auditTransportEvidence", nativeTransportEvidence.get().asFile.absolutePath)
    systemProperty("remozio.test.routingEvidence", nativeTransportEvidence.get().asFile.absolutePath)
}

// The full approvalFlowTest includes these cases. This task keeps the focused native routing check small.
tasks.register<Test>("routingFlowTest") {
    description = "Runs the synthetic native Swift and Kotlin routing exchange."
    group = "verification"
    dependsOn(tasks.testClasses)
    testClassesDirs = sourceSets.test.get().output.classesDirs
    classpath = sourceSets.test.get().runtimeClasspath
    filter { includeTestsMatching("dev.remozio.phone.crypto.TLSInteropTest.routing*") }
    val peer = rootProject.layout.projectDirectory.file(".build/approval-flow/TLSPeer")
    inputs.file(peer)
    systemProperty("remozio.test.tlsPeer", peer.asFile.absolutePath)
    val evidence = layout.buildDirectory.dir("reports/routing-evidence")
    outputs.dir(evidence)
    systemProperty("remozio.test.routingEvidence", evidence.get().asFile.absolutePath)
}

// Included by approvalFlowTest. Keep the native audit/routing regression path small during development.
tasks.register<Test>("auditTransportFlowTest") {
    description = "Runs native Swift and Kotlin audit transport with routing regression controls."
    group = "verification"
    dependsOn(tasks.testClasses)
    testClassesDirs = sourceSets.test.get().output.classesDirs
    classpath = sourceSets.test.get().runtimeClasspath
    filter {
        includeTestsMatching("dev.remozio.phone.crypto.TLSInteropTest.audit*")
        includeTestsMatching("dev.remozio.phone.crypto.TLSInteropTest.routing*")
    }
    val peer = rootProject.layout.projectDirectory.file(".build/approval-flow/TLSPeer")
    inputs.file(peer)
    systemProperty("remozio.test.tlsPeer", peer.asFile.absolutePath)
    val evidence = layout.buildDirectory.dir("reports/audit-transport-evidence")
    outputs.dir(evidence)
    systemProperty("remozio.test.auditTransportEvidence", evidence.get().asFile.absolutePath)
    systemProperty("remozio.test.routingEvidence", evidence.get().asFile.absolutePath)
}
