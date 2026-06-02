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

// Pin the bytecode target to JVM 21 (LTS) for both Java and Kotlin so the
// .class files line up. The user's runtime JDK can be anything ≥ 21 (we
// run on Homebrew openjdk@25 today). Kotlin 2.2 doesn't yet support
// JVM_25 target which causes a Java/Kotlin target mismatch if we let it
// auto-pick.
configure<JavaPluginExtension> {
    sourceCompatibility = JavaVersion.VERSION_21
    targetCompatibility = JavaVersion.VERSION_21
}
tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile>().configureEach {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_21)
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
