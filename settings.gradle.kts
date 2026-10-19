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
include(":protocol-kotlin")
project(":protocol-kotlin").projectDir = file("protocol/kotlin")
include(":android-app")
project(":android-app").projectDir = file("android/app")
include(":phone-core")
project(":phone-core").projectDir = file("phone/core")
include(":phone-ui")
project(":phone-ui").projectDir = file("phone/ui")
include(":dev-invitation")
project(":dev-invitation").projectDir = file("tools/dev-invitation")
