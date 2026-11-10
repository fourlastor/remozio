pluginManagement {
    repositories {
        google()
        gradlePluginPortal()
        mavenCentral()
    }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}
rootProject.name = "remozio"
// Android lint checks gradle/libs.versions.toml and the Gradle wrapper only for the first included project,
// so the app, the one project lint analyzes, comes first.
include(":android-app")
project(":android-app").projectDir = file("android/app")
include(":protocol-kotlin")
project(":protocol-kotlin").projectDir = file("protocol/kotlin")
include(":phone-pairing")
project(":phone-pairing").projectDir = file("phone/pairing")
include(":phone-enrollment")
project(":phone-enrollment").projectDir = file("phone/enrollment")
include(":phone-core")
project(":phone-core").projectDir = file("phone/core")
include(":phone-ui")
project(":phone-ui").projectDir = file("phone/ui")
include(":dev-invitation")
project(":dev-invitation").projectDir = file("tools/dev-invitation")
