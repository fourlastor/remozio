plugins {
    alias(libs.plugins.kotlin.multiplatform)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.compose.multiplatform)
}

kotlin {
    jvmToolchain(21)
    // The JVM target runs the shared state tests on Linux; no app consumes it.
    jvm()
    listOf(iosArm64(), iosSimulatorArm64()).forEach { target ->
        target.binaries.framework {
            baseName = "RemozioUI"
            isStatic = true
            // Swift implements the pairing transport, so its types must be visible in the framework.
            export(project(":phone-pairing"))
        }
    }

    sourceSets {
        commonMain.dependencies {
            implementation(project(":protocol-kotlin"))
            api(project(":phone-pairing"))
            implementation(libs.compose.multiplatform.runtime)
            implementation(libs.compose.multiplatform.animation)
            implementation(libs.compose.multiplatform.foundation)
            implementation(libs.compose.multiplatform.ui)
        }
        commonTest.dependencies {
            implementation(kotlin("test"))
        }
    }
}
