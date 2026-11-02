plugins {
    kotlin("jvm")
    `java-test-fixtures`
}

kotlin { jvmToolchain(21) }

dependencies {
    implementation(project(":protocol-kotlin"))
    testFixturesImplementation(project(":protocol-kotlin"))
    implementation("io.ktor:ktor-websockets:3.6.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.11.0")
    testImplementation("org.bouncycastle:bcprov-jdk18on:1.86")
    testImplementation("com.squareup.okhttp3:mockwebserver3:5.5.0")
    testImplementation("com.squareup.okhttp3:okhttp-tls:5.5.0")
    testImplementation(kotlin("test-junit"))
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.11.0")
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.11.0")
}

val capture = rootProject.layout.projectDirectory.file("android/app/src/debug/res/raw/sample_command.cbor")
tasks.withType<Test>().configureEach {
    useJUnit()
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

tasks.test { exclude("**/ApprovalFlowTest.class", "**/AuditFlowTest.class", "**/HPKEInteropTest.class", "**/TLSInteropTest.class", "**/PairingSetupInteropTest.class") }

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
