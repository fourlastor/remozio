plugins {
    kotlin("jvm")
    application
}

kotlin { jvmToolchain(21) }

dependencies {
    implementation(project(":protocol-kotlin"))
    implementation("com.google.zxing:core:3.5.3")
    testImplementation(kotlin("test-junit"))
    testImplementation("junit:junit:4.13.2")
}

application {
    mainClass.set("dev.remozio.devinvitation.DevInvitationKt")
    applicationName = "dev-invitation"
}

tasks.test { useJUnit() }

// `./gradlew :dev-invitation:run --args="--png /tmp/invitation.png"`; relative paths resolve from the repository root.
tasks.named<JavaExec>("run") { workingDir = rootProject.layout.projectDirectory.asFile }
