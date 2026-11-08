plugins {
    alias(libs.plugins.kotlin.jvm)
    application
}

kotlin { jvmToolchain(21) }

dependencies {
    implementation(project(":protocol-kotlin"))
    implementation(libs.zxing.core)
    testImplementation(kotlin("test-junit"))
    testImplementation(libs.junit)
}

application {
    mainClass.set("dev.remozio.devinvitation.DevInvitationKt")
    applicationName = "dev-invitation"
}

tasks.test { useJUnit() }

// `./gradlew :dev-invitation:run --args="--png /tmp/invitation.png"`; relative paths resolve from the repository root.
tasks.named<JavaExec>("run") { workingDir = rootProject.layout.projectDirectory.asFile }
