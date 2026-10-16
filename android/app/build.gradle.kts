plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
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
    namespace = "dev.remozio.android"
    compileSdk = 37
    buildToolsVersion = "37.0.0"
    defaultConfig {
        applicationId = "dev.remozio.android"
        minSdk = 37
        targetSdk = 37
        versionCode = releaseCode
        versionName = releaseVersion
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
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.11.0")
    implementation("androidx.core:core:1.19.1")
    implementation("com.google.android.gms:play-services-code-scanner:16.1.0")
    implementation(platform("androidx.compose:compose-bom:2026.09.00"))
    implementation("androidx.activity:activity-compose:1.13.0")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.11.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.11.0")
    implementation("androidx.lifecycle:lifecycle-viewmodel:2.11.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.11.0")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.foundation:foundation")
    implementation("androidx.compose.material3:material3:1.5.0-alpha29")
    testImplementation(testFixtures(project(":phone-core")))
    testImplementation("org.xerial:sqlite-jdbc:3.53.4.0")
    testImplementation(kotlin("test-junit"))
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.11.0")
}

val commandCaptureFixture = rootProject.layout.projectDirectory.file("android/app/src/debug/res/raw/sample_command.cbor")
val commandStreamVectors = rootProject.layout.projectDirectory.file("protocol/vectors/command-capture-v3.json")
tasks.withType<Test>().configureEach {
    inputs.file(commandStreamVectors)
    systemProperty("remozio.test.commandStreamVectors", commandStreamVectors.asFile.absolutePath)
    inputs.file(commandCaptureFixture)
    systemProperty("remozio.test.commandCapture", commandCaptureFixture.asFile.absolutePath)
}
