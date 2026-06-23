// Pure-Kotlin port of @elabify/core. Cross-binding equivalence with the
// TypeScript reference + the Swift port is enforced by the KAT corpus at
// ../../test-vectors/, which the test target reads at runtime.
//
// Build:    gradle build
// Test:     gradle test
// KAT only: gradle test --tests com.elabify.core.KatRunnerTest

buildscript {
    repositories {
        mavenCentral()
    }
    dependencies {
        // Plugin lookup via the plugins {} block had trouble with Gradle 9.5
        // and the kotlin-gradle-plugin marker. Going through buildscript +
        // apply plugin uses the same Maven Central artifact directly and
        // sidesteps the plugin-portal indirection.
        classpath("org.jetbrains.kotlin:kotlin-gradle-plugin:2.2.0")
    }
}

apply(plugin = "org.jetbrains.kotlin.jvm")

group = "com.elabify"
version = "0.1.0"

// Repositories for application-side dependencies are declared in
// settings.gradle.kts (dependencyResolutionManagement), so do not redeclare
// them here — Gradle 9 errors out on duplicate repository declarations
// when FAIL_ON_PROJECT_REPOS is set.

dependencies {
    // org.json for the KAT-vector JSON reader. Tiny, well-known, no
    // transitive deps. Avoids pulling in a full Codable-equivalent
    // framework for what's a one-shot test-time read.
    "testImplementation"("org.json:json:20240303")
    "testImplementation"("org.jetbrains.kotlin:kotlin-test")
}

// Pin the bytecode target to JVM 17 (LTS) for both Java and Kotlin. 17 is
// the Android baseline (AGP compileOptions target 17), so the Android SDK +
// app consume this artifact and run its unit tests on JDK 17 without a
// class-file-version mismatch. The runtime JDK can be anything >= 17; we
// pin the *output* so .class files line up and don't auto-pick a newer
// target than Android can dex/load.
configure<JavaPluginExtension> {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}
tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile>().configureEach {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

tasks.named<Test>("test") {
    useJUnitPlatform()
    testLogging {
        events("passed", "failed", "skipped")
        showStandardStreams = true
    }
    // The KAT runner walks up from the test classpath to find
    // ../../test-vectors. Pass the repo-relative path via a system
    // property so the test isn't sensitive to CWD.
    systemProperty(
        "elabify.testVectorsPath",
        layout.projectDirectory.dir("../../test-vectors").asFile.absolutePath
    )
}
