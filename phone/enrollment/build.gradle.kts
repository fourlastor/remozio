plugins { alias(libs.plugins.kotlin.multiplatform) }

kotlin {
    jvmToolchain(21)
    compilerOptions { freeCompilerArgs.add("-Xexpect-actual-classes") }
    jvm()
    iosArm64()
    iosSimulatorArm64()

    sourceSets {
        commonMain.dependencies {
            api(project(":protocol-kotlin"))
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

// Native tests cannot read files through system properties, so the vector becomes a Kotlin source.
val generateEnrollmentTestVectors by tasks.registering {
    val vectors = layout.projectDirectory.file("vectors/enrollment-archive-v1.json")
    val output = layout.buildDirectory.file("generated/enrollmentTestVectors/dev/remozio/phone/enrollment/TestVectors.kt")
    inputs.file(vectors)
    outputs.file(output)
    doLast {
        val text = vectors.asFile.readText()
        check(text.isNotBlank()) { "Empty vector file ${vectors.asFile}" }
        val chunks = text.chunked(8_000).joinToString(",\n        ") { "\"\"\"" + it.replace("$", "\${'$'}") + "\"\"\"" }
        output.get().asFile.apply { parentFile.mkdirs() }.writeText(
            "package dev.remozio.phone.enrollment\n\n/** Generated from vectors/. Do not edit. */\ninternal object TestVectors {\n" +
                "    val enrollmentArchive: String = listOf(\n        $chunks,\n    ).joinToString(\"\")\n}\n")
    }
}
kotlin.sourceSets.commonTest { kotlin.srcDir(layout.buildDirectory.dir("generated/enrollmentTestVectors")) }
tasks.matching { it.name.startsWith("compileTestKotlin") }
    .configureEach { dependsOn(generateEnrollmentTestVectors) }
