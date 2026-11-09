plugins { alias(libs.plugins.kotlin.multiplatform) }

kotlin {
    jvmToolchain(21)
    jvm()
    iosArm64()
    iosSimulatorArm64()

    sourceSets {
        commonMain.dependencies {
            api(project(":protocol-kotlin"))
            api(libs.kotlinx.coroutines.core)
            api(libs.kotlinx.io.core)
        }
        commonTest.dependencies {
            implementation(libs.kotlinx.serialization.json)
            implementation(kotlin("test"))
            implementation(libs.kotlinx.coroutines.test)
        }
        jvmTest.dependencies {
            implementation(kotlin("test-junit"))
            implementation(libs.junit)
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
