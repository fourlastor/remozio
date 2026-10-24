plugins {
    kotlin("multiplatform")
    kotlin("plugin.compose")
    id("org.jetbrains.compose")
}

kotlin {
    jvmToolchain(21)
    // The JVM target runs the shared state tests on Linux; no app consumes it.
    jvm()
    listOf(iosArm64(), iosSimulatorArm64()).forEach { target ->
        target.binaries.framework {
            baseName = "RemozioUI"
            isStatic = true
        }
    }

    sourceSets {
        commonMain.dependencies {
            implementation(project(":protocol-kotlin"))
            implementation("org.jetbrains.compose.runtime:runtime:1.12.2")
            implementation("org.jetbrains.compose.animation:animation:1.12.2")
            implementation("org.jetbrains.compose.foundation:foundation:1.12.2")
            implementation("org.jetbrains.compose.ui:ui:1.12.2")
        }
        commonTest.dependencies {
            implementation(kotlin("test"))
        }
    }
}
