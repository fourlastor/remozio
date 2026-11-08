plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
}

val releaseVersion = providers.gradleProperty("remozioVersionName").orElse("0.1.0").get()
val releaseCode = providers.gradleProperty("remozioVersionCode").orElse("1").get().toIntOrNull()
require(releaseCode != null && releaseCode in 1..2_100_000_000) { "Invalid remozioVersionCode" }
require(releaseVersion.length <= 128 && Regex("(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*)?(?:\\+[0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*)?").matches(releaseVersion)) {
    "Invalid remozioVersionName"
}
require(releaseVersion.substringBefore('+').substringAfter('-', "").split('.').none {
    it.length > 1 && it.all(Char::isDigit) && it.startsWith('0')
}) { "Invalid numeric prerelease identifier" }
require(releaseVersion.substringBefore('-').substringBefore('+').split('.').all { it.toIntOrNull() != null }) {
    "Version component exceeds updater range"
}

android {
    namespace = "dev.sebastiano.remozio.android"
    compileSdk = 37
    buildToolsVersion = "37.0.0"
    defaultConfig {
        applicationId = "dev.sebastiano.remozio.android"
        minSdk = 37
        targetSdk = 37
        versionCode = releaseCode
        versionName = releaseVersion
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }
    buildTypes {
        debug { applicationIdSuffix = ".debug" }
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"))
        }
    }
    buildFeatures { compose = true }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }
}

kotlin { jvmToolchain(21) }

dependencies {
    implementation(project(":protocol-kotlin"))
    implementation(project(":phone-core"))
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.androidx.core)
    implementation(libs.play.services.code.scanner)
    implementation(libs.firebase.messaging)
    implementation(libs.play.services.cloud.messaging)
    implementation(libs.androidx.work.runtime.ktx)
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.lifecycle.viewmodel)
    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.foundation)
    implementation(libs.androidx.compose.material3)
    testImplementation(testFixtures(project(":phone-core")))
    testImplementation(libs.sqlite.jdbc)
    testImplementation(kotlin("test-junit"))
    testImplementation(libs.junit)
    testImplementation(libs.kotlinx.coroutines.test)
    androidTestImplementation(platform(libs.androidx.compose.bom))
    androidTestImplementation(libs.androidx.compose.ui.test.junit4)
    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.androidx.test.espresso.core)
    // Keep the debug runtime aligned with the instrumented tests.
    debugImplementation(libs.androidx.concurrent.futures.ktx)
    debugImplementation(libs.errorprone.annotations)
}

val commandCaptureFixture = rootProject.layout.projectDirectory.file("android/app/src/debug/res/raw/sample_command.cbor")
val commandStreamVectors = rootProject.layout.projectDirectory.file("protocol/vectors/command-capture-v3.json")
val linuxCommandCaptureVectors = rootProject.layout.projectDirectory.file("protocol/vectors/command-capture-v4.json")
tasks.withType<Test>().configureEach {
    inputs.file(commandStreamVectors)
    systemProperty("remozio.test.commandStreamVectors", commandStreamVectors.asFile.absolutePath)
    inputs.file(linuxCommandCaptureVectors)
    systemProperty("remozio.test.linuxCommandCaptureVectors", linuxCommandCaptureVectors.asFile.absolutePath)
    inputs.file(commandCaptureFixture)
    systemProperty("remozio.test.commandCapture", commandCaptureFixture.asFile.absolutePath)
}
