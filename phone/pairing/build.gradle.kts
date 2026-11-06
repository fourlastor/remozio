plugins { kotlin("multiplatform") }

kotlin {
    jvmToolchain(21)
    jvm()
    iosArm64()
    iosSimulatorArm64()

    sourceSets {
        commonMain.dependencies {
            api(project(":protocol-kotlin"))
            api("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.11.0")
            api("org.jetbrains.kotlinx:kotlinx-io-core:0.9.1")
        }
        commonTest.dependencies {
            implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.11.0")
            implementation(kotlin("test"))
            implementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.11.0")
        }
        jvmTest.dependencies {
            implementation(kotlin("test-junit"))
            implementation("junit:junit:4.13.2")
        }
    }
}

tasks.named<Test>("jvmTest") { useJUnit() }

// Native tests cannot read files through system properties, so the vectors they need become Kotlin sources.
val generatePairingTestVectors by tasks.registering {
    val vectors = rootProject.layout.projectDirectory.file("protocol/vectors/pairing-setup-v1.json")
    val output = layout.buildDirectory.file("generated/pairingTestVectors/dev/remozio/pairing/TestVectors.kt")
    inputs.file(vectors)
    outputs.file(output)
    doLast {
        val text = vectors.asFile.readText()
        check(text.isNotBlank()) { "Empty vector file ${vectors.asFile}" }
        val chunks = text.chunked(8_000).joinToString(",\n        ") { "\"\"\"" + it.replace("$", "\${'$'}") + "\"\"\"" }
        output.get().asFile.apply { parentFile.mkdirs() }.writeText(
            "package dev.remozio.pairing\n\n/** Generated from protocol/vectors. Do not edit. */\ninternal object TestVectors {\n" +
                "    val pairingSetup: String = listOf(\n        $chunks,\n    ).joinToString(\"\")\n}\n")
    }
}
kotlin.sourceSets.commonTest { kotlin.srcDir(layout.buildDirectory.dir("generated/pairingTestVectors")) }
tasks.matching { it.name.startsWith("compileTestKotlin") }
    .configureEach { dependsOn(generatePairingTestVectors) }
